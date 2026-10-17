"""Real browser regression against an isolated local server (no API mocks).

Install Playwright/Chromium; set PUBLIC_UI_URL if not http://127.0.0.1:5476.
Run: python scripts/public-file-ui-regression.py /absolute/path/to/fresh-evidence-directory
Do not use an existing production instance; this creates transient collaboration state.
"""
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, expect
from public_ui_fixture import ORIGIN, write, output_directory
sys.stdout.reconfigure(encoding='utf8')
out=output_directory(sys.argv[1]);errors=[];console=[];uploads=[];observations=[]
payload=bytes(range(256))*8192
expected_hash=hashlib.sha256(payload).hexdigest()
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True)
    contexts=[];pages=[]
    try:
        for name in ['验收发送端','验收接收端']:
            context=browser.new_context(viewport=dict(width=1440,height=1080),reduced_motion='reduce',accept_downloads=True)
            contexts.append(context)
            context.route('https://www.googletagmanager.com/**',lambda route:route.fulfill(status=204,body=''))
            context.add_init_script("localStorage.setItem('public-transfer-client-name',"+json.dumps(name)+");localStorage.setItem('specus_theme','light');sessionStorage.setItem('public-transfer-receive-confirmation','true');")
            context.add_init_script('''window.acceptanceRtc=[];window.RTCPeerConnection=new Proxy(window.RTCPeerConnection,{construct(Target,args){const pc=Reflect.construct(Target,args);window.acceptanceRtc.push(pc);return pc;}});''')
            page=context.new_page();pages.append(page)
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.on('console',lambda msg:console.append(dict(type=msg.type,text=msg.text)) if msg.type in ['error','warning'] else None)
            page.on('request',lambda req:uploads.append(dict(path=urlparse(req.url).path,method=req.method)) if req.method not in ['GET','OPTIONS'] and re.search('presign|upload|complete',urlparse(req.url).path) else None)
            page.goto(ORIGIN+'/#/transfer');page.wait_for_load_state('networkidle')
            expect(page.get_by_role('heading',name='互传',exact=True)).to_be_visible()
        a,b=pages
        def select_peer(page,name):
            choice=page.get_by_role('radiogroup',name='发送目标设备').get_by_role('radio',name=re.compile(name));expect(choice).to_be_visible();choice.click();expect(choice).to_have_attribute('aria-checked','true')
        select_peer(a,'验收接收端');select_peer(b,'验收发送端')
        for label,page in [('sender',a),('receiver',b)]:
            (out/(label+'-initial-aria.txt')).write_text(page.locator('body').aria_snapshot(),encoding='utf8')
        a.locator('#public-transfer-file-input').set_input_files(dict(name='native-migration-验收.bin',mimeType='application/octet-stream',buffer=payload))
        preview=a.get_by_role('dialog',name='发送前确认');expect(preview).to_contain_text('尚未发送任何文件内容')
        expect(b.get_by_role('button',name='接收',exact=True)).to_have_count(0);assert not uploads
        preview.get_by_role('button',name='确认发送',exact=True).click()
        expect(b.get_by_role('button',name='接收',exact=True)).to_be_visible()
        expect(b.get_by_role('button',name='保存到设备',exact=True)).to_have_count(0)
        progress=a.get_by_role('progressbar',name='上传进度',exact=True);expect(progress).to_have_count(1)
        waiting_progress=progress.evaluate('(e)=>({outer:e.outerHTML,trackCount:e.querySelectorAll("[data-slot=progress-bar-track]").length,fillCount:e.querySelectorAll("[data-slot=progress-bar-fill]").length,height:e.getBoundingClientRect().height})')
        write(out,'waiting-progress.json',waiting_progress)
        a.screenshot(path=str(out/'waiting-confirmation.png'),full_page=True,animations='disabled')
        observations.append('Selecting file creates explicit preflight; no receiver offer before confirm; real offer waits for explicit receiving consent; zero cloud uploads')
        b.get_by_role('button',name='接收',exact=True).click()
        expect(b.get_by_role('button',name='保存到设备',exact=True)).to_be_visible(timeout=30000)
        (out/'received-aria.txt').write_text(b.locator('body').aria_snapshot(),encoding='utf8')
        with b.expect_download() as result:
            b.get_by_role('button',name='保存到设备',exact=True).click()
        download=result.value;assert download.failure() is None
        download.save_as(out/'received.bin')
        received_hash=hashlib.sha256((out/'received.bin').read_bytes()).hexdigest()
        assert received_hash==expected_hash and (out/'received.bin').stat().st_size==len(payload)
        observations.append('Real 2MiB browser-to-browser transfer completed; browser download size and SHA256 match exact original bytes')
        stats=[]
        for page in pages:
            stats.append(page.evaluate('''async()=>{const results=[];for(const pc of acceptanceRtc){const stats=await pc.getStats();results.push({connection:pc.connectionState,pairs:[...stats.values()].filter(s=>s.type==='candidate-pair'&&s.state==='succeeded'&&s.nominated).map(s=>({nominated:s.nominated,bytesSent:s.bytesSent,bytesReceived:s.bytesReceived})),dataChannels:[...stats.values()].filter(s=>s.type==='data-channel').map(s=>({state:s.state,bytesSent:s.bytesSent,bytesReceived:s.bytesReceived}))});}return results;}'''))
        assert any(item['connection']=='connected' and item['pairs'] for side in stats for item in side),stats
        assert not errors,errors
        assert not uploads,uploads
        write(out,'file-bytes-proof.json',dict(observations=observations,size=len(payload),sentSHA256=expected_hash,receivedSHA256=received_hash,suggestedFilename=download.suggested_filename,rtcStats=stats,waitingProgress=waiting_progress,pageErrors=errors,console=console,cloudUploads=uploads))
        # Same assertion deliberately retained for old and repaired component structures.
        assert waiting_progress['trackCount']==1 and waiting_progress['fillCount']==1 and waiting_progress['height']>0,'Native visible progress track/fill missing'
        print('PASS real two-browser2MiB transfer, explicit consent, matching download bytes, connected WebRTC and visible progress')
    except Exception:
        write(out,'partial-proof.json',dict(observations=observations,pageErrors=errors,console=console,uploads=uploads))
        for index,page in enumerate(pages):
            (out/('failure-'+str(index)+'-aria.txt')).write_text(page.locator('body').aria_snapshot(),encoding='utf8')
            page.screenshot(path=str(out/('failure-'+str(index)+'.png')),full_page=True,animations='disabled')
        raise
    finally:
        for context in contexts:context.close()
        browser.close()
