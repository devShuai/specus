"""Real browser regression against an isolated local server (no API mocks).

Install Playwright/Chromium; set PUBLIC_UI_URL if not http://127.0.0.1:5476.
Run: python scripts/public-diagram-ui-regression.py /absolute/path/to/fresh-evidence-directory
Do not use an existing production instance; this creates transient collaboration state.
"""
import hashlib
import re
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright, expect
from public_ui_fixture import ORIGIN, write, output_directory
sys.stdout.reconfigure(encoding='utf8')
out=output_directory(sys.argv[1]);errors=[];console=[];observations=[]
with sync_playwright() as p:
    browser=p.chromium.launch(headless=True)
    try:
        context=browser.new_context(viewport=dict(width=1440,height=1080),reduced_motion='reduce',accept_downloads=True)
        context.route('https://www.googletagmanager.com/**',lambda route:route.fulfill(status=204,body=''))
        context.add_init_script("localStorage.setItem('specus_theme','light');")
        page=context.new_page();page.on('pageerror',lambda error:errors.append(str(error)))
        page.on('console',lambda msg:console.append(dict(type=msg.type,text=msg.text)) if msg.type in ['error','warning'] else None)
        try:
            page.goto(ORIGIN+'/#/diagram');page.wait_for_load_state('networkidle');expect(page.get_by_label('专业流程图画布',exact=True)).to_be_visible()
            for name in ['编辑菜单','排列菜单','协作菜单','视图菜单','文件菜单']:expect(page.get_by_role('button',name=name,exact=True)).to_have_count(1)
            assert page.locator('button button,button [role=button]').count()==0
            page.get_by_role('button',name='未命名流程图',exact=True).click()
            rename=page.get_by_role('dialog',name='重命名流程图',exact=True);expect(rename).to_be_visible()
            name=rename.get_by_role('textbox',name='流程图名称',exact=True);name.fill('UI3验收流程图');name.press('Enter')
            expect(page.get_by_role('dialog')).to_have_count(0);expect(page.get_by_role('button',name='UI3验收流程图',exact=True)).to_be_visible()
            observations.append('Single native toolbar buttons; labelled editor dialog renames session document with Enter')
            page.get_by_role('button',name='矩形 通用容器',exact=True).click()
            expect(page.get_by_text('1 节点',exact=True)).to_be_visible()
            page.get_by_role('button',name='协作菜单',exact=True).click()
            (out/'collaboration-menu-aria.txt').write_text(page.locator('body').aria_snapshot(),encoding='utf8')
            page.get_by_role('menuitem',name=re.compile('添加评论')).click()
            comment=page.get_by_role('dialog',name=re.compile('评论(选中元素|当前页面)'))
            expect(comment).to_be_visible();text=comment.get_by_role('textbox',name='评论内容',exact=True)
            value='UI3 评论首行\n'+'\n'.join('第'+str(n)+'行：多行文本与自动高度' for n in range(12))
            text.fill(value)
            dimensions=text.evaluate('(e)=>({height:e.clientHeight,line:parseFloat(getComputedStyle(e).lineHeight),padding:parseFloat(getComputedStyle(e).paddingTop)+parseFloat(getComputedStyle(e).paddingBottom),overflow:getComputedStyle(e).overflowY})')
            assert dimensions['height']>=4*dimensions['line'] and dimensions['height']<=9*dimensions['line']+dimensions['padding']+2,dimensions
            assert dimensions['overflow']=='auto',dimensions
            page.screenshot(path=str(out/'multiline-comment.png'),full_page=True,animations='disabled')
            text.press('Control+Enter');expect(page.get_by_role('dialog')).to_have_count(0)
            expect(page.get_by_text(re.compile('UI3 评论首行'))).to_be_visible()
            observations.append('Native menu inserts node; multiline comment is bounded4..9rows and Control+Enter actually commits to inspector')
            file_button=page.get_by_role('button',name='文件菜单',exact=True);file_button.focus();page.keyboard.press('Enter')
            export=page.get_by_role('menuitem',name=re.compile('快速导出 PNG'));expect(export).to_be_enabled()
            with page.expect_download() as result:export.click()
            download=result.value;assert download.failure() is None
            download.save_as(out/'diagram.png');data=(out/'diagram.png').read_bytes()
            assert data.startswith(b'\x89PNG\r\n\x1a\n') and len(data)>100
            observations.append('Keyboard-operated native file menu exports actual graph to valid PNG bytes')
            page.screenshot(path=str(out/'editor-complete.png'),full_page=True,animations='disabled')
            assert not errors,errors;assert not console,console
            write(out,'proof.json',dict(observations=observations,pageErrors=errors,console=console,textarea=dimensions,pngBytes=len(data),pngSHA256=hashlib.sha256(data).hexdigest()))
            print('PASS native diagram rename, insert, multiline keyboard commit and actual PNG export')
        except Exception:
            write(out,'partial-proof.json',dict(observations=observations,pageErrors=errors,console=console));(out/'failure-aria.txt').write_text(page.locator('body').aria_snapshot(),encoding='utf8');page.screenshot(path=str(out/'failure.png'),full_page=True,animations='disabled');raise
    finally:browser.close()
