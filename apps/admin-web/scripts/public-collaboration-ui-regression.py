"""Real browser regression against an isolated local server (no API mocks).

Install Playwright/Chromium; set PUBLIC_UI_URL if not http://127.0.0.1:5476.
Run: python scripts/public-collaboration-ui-regression.py /absolute/path/to/fresh-evidence-directory
Do not use an existing production instance; this creates transient collaboration state.
"""
import json
import gzip
import hashlib
import re
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from public_ui_fixture import ORIGIN, write, output_directory
sys.stdout.reconfigure(encoding='utf8')
out=output_directory(sys.argv[1]);errors=[];console=[];observations=[]
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True);contexts=[];pages=[]
    try:
        for name in ['验收发送端','验收接收端','未邀请观察端']:
            context=browser.new_context(viewport=dict(width=1440,height=1080),reduced_motion='reduce',accept_downloads=True)
            contexts.append(context);context.route('https://www.googletagmanager.com/**',lambda route:route.fulfill(status=204,body=''))
            context.add_init_script("localStorage.setItem('public-transfer-client-name',"+json.dumps(name)+");localStorage.setItem('specus_theme','light');")
            page=context.new_page();pages.append(page);page.on('pageerror',lambda error:errors.append(str(error)))
            page.on('console',lambda msg:console.append(dict(type=msg.type,text=msg.text)) if msg.type in ['error','warning'] else None)
            page.goto(ORIGIN+'/#/transfer');page.wait_for_load_state('networkidle');expect(page.get_by_role('heading',name='互传',exact=True)).to_be_visible()
        a,b,c=pages
        for page,name in [(a,'验收接收端'),(b,'验收发送端')]:
            choice=page.get_by_role('radiogroup',name='发送目标设备').get_by_role('radio',name=re.compile(name));expect(choice).to_be_visible();choice.click()
            page.get_by_role('tab',name='文字与链接',exact=True).click()
            (out/('clipboard-'+str(pages.index(page))+'-aria.txt')).write_text(page.locator('body').aria_snapshot(),encoding='utf8')
        marker='UI3 nearby 文本验收 20261018'
        a.get_by_role('textbox',name='添加剪贴板内容').fill(marker);a.get_by_role('button',name='发送文字',exact=True).click()
        expect(b.get_by_text(marker,exact=True)).to_be_visible()
        c.get_by_role('tab',name='文字与链接',exact=True).click();expect(c.get_by_text(marker,exact=True)).to_have_count(0)
        observations.append('Actual nearby clipboard text arrived in independent receiver browser')
        a.get_by_role('button',name='添加设备',exact=True).first.click()
        a.get_by_role('dialog',name='添加设备',exact=True).get_by_role('button',name='生成邀请',exact=True).click()
        a.get_by_role('dialog',name='创建共享房间？',exact=True).get_by_role('button',name='继续',exact=True).click()
        invite=a.get_by_role('dialog',name='添加设备',exact=True)
        code_field=invite.locator('.font-mono.text-2xl');expect(code_field).to_have_text(re.compile(r'\d{4}\s+\d{4}'))
        code=code_field.inner_text().replace(' ','')
        (out/'owner-invite-private-aria.txt').write_text(invite.aria_snapshot(),encoding='utf8')
        invite.get_by_role('button',name='Close',exact=True).click()
        b.get_by_role('button',name='添加设备',exact=True).first.click();join=b.get_by_role('dialog',name='添加设备',exact=True)
        join.get_by_role('tab',name='输入配对码',exact=True).click();join.get_by_role('textbox',name='对方的配对码').fill(code);join.get_by_role('button',name='连接对方',exact=True).click()
        b.get_by_role('dialog',name='加入新的共享房间？',exact=True).get_by_role('button',name='继续',exact=True).click()
        expect(b.get_by_text(re.compile('配对成功，已以可编辑身份加入'))).to_be_visible()
        observations.append('Explicit room switch confirmation + real generated pairing code + editor redemption completed')
        for label,page in [('owner',a),('editor',b)]:
            page.get_by_role('tab',name='多人白板',exact=True).click();expect(page.get_by_label('多人白板画布')).to_be_visible()
            page.wait_for_load_state('networkidle');(out/(label+'-board-aria.txt')).write_text(page.locator('body').aria_snapshot(),encoding='utf8')
            page.screenshot(path=str(out/(label+'-board.png')),full_page=True,animations='disabled')
        c.get_by_role('tab',name='多人白板',exact=True).click();expect(c.get_by_text(re.compile(r'0 笔 · 0 个对象$'))).to_be_visible()
        a.get_by_role('button',name='插入菜单',exact=True).click()
        (out/'insert-menu-aria.txt').write_text(a.locator('body').aria_snapshot(),encoding='utf8')
        a.get_by_role('menuitem',name='文本',exact=True).click()
        canvas=a.get_by_label('多人白板画布');canvas.click(position=dict(x=180,y=150))
        text=a.get_by_role('textbox',name='白板文本框内容',exact=True);expect(text).to_be_visible()
        board_marker='UI3 白板双端实际同步 20261018'
        text.fill(board_marker);text.press('Control+Enter')
        for page in [a,b]:expect(page.get_by_text(re.compile(r'0 笔 · 1 个对象$'))).to_be_visible()
        expect(c.get_by_text(re.compile(r'0 笔 · 0 个对象$'))).to_be_visible()
        exported=[]
        for label,page in [('owner',a),('editor',b)]:
            page.get_by_role('button',name='文件菜单',exact=True).click()
            with page.expect_download() as download:
                page.get_by_role('menuitem',name='导出白板',exact=True).click()
            file=download.value;assert file.failure() is None
            target=out/(label+'.stwb');file.save_as(target)
            data=target.read_bytes();assert data[:6]==b'STWB1\x00'
            document=json.loads(gzip.decompress(data[6:]).decode('utf8'))
            assert document['format']=='specus-whiteboard' and document['version']==1
            assert len(document['objects'])==1 and document['objects'][0]['text']==board_marker,document
            exported.append(dict(label=label,sha256=hashlib.sha256(data).hexdigest(),document=document))
            page.screenshot(path=str(out/(label+'-synchronized.png')),full_page=True,animations='disabled')
        assert exported[0]['document']['objects']==exported[1]['document']['objects']
        observations.append('Actual owner inserted text using native dropdown and canvas; editor received same object; independent UI exports decode STWB1/gzip to identical object text/source/geometry')
        observations.append('Third uninivited nearby browser received neither addressed clipboard text nor private-room whiteboard object')
        c.screenshot(path=str(out/'uninivited-local-board.png'),full_page=True,animations='disabled')
        write(out,'proof.json',dict(observations=observations,pageErrors=errors,console=console,exports=exported))
        assert not errors,errors
        assert not console,console
        print('PASS real addressed clipboard, explicit pairing, synchronized whiteboard object and identical UI exports; uninivited browser isolated')
    except Exception:
        write(out,'partial-proof.json',dict(observations=observations,pageErrors=errors,console=console))
        for index,page in enumerate(pages):
            (out/('failure-'+str(index)+'-aria.txt')).write_text(page.locator('body').aria_snapshot(),encoding='utf8');page.screenshot(path=str(out/('failure-'+str(index)+'.png')),full_page=True,animations='disabled')
        raise
    finally:
        for context in contexts:context.close()
        browser.close()
