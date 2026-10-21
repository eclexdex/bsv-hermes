"""Chromium acceptance of the actual composed receipt report, offline and inert."""
import argparse
import json
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright, expect

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from bsv_hermes.receipts import evidence, viewer


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--html',type=Path);args=p.parse_args()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    bundle=json.loads((ROOT/'tests/receipt_vectors/contract/golden.json').read_text())
    artifacts=json.loads((ROOT/'tests/receipt_vectors/contract/artifacts.json').read_text())
    grants={}
    for i,(name,raw) in enumerate(artifacts.items()):
        target=out/('artifact-'+str(i));target.write_bytes(bytes.fromhex(raw));grants[name]=target
    report=evidence.verify(bundle,grants)
    value={'source_label':'SYNTHETIC offline receipt; not a public transaction','bundle':bundle,'report':report}
    html=args.html.resolve() if args.html else out/'viewer.html'
    if args.html is None: html.write_text(viewer.generate(value))
    (out/'viewer-input.json').write_text(json.dumps(value))
    checks=[];errors=[];remote=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(channel='chrome',headless=True)
        page=browser.new_page(viewport={'width':1600,'height':1000},device_scale_factor=2)
        page.on('pageerror',lambda e:errors.append(str(e)))
        page.on('request',lambda r:remote.append(r.url) if r.url.startswith(('http:','https:')) else None)
        page.goto(html.as_uri())
        assert page.locator('.card').count()==6
        if not args.html:
            assert page.locator('.status').first.inner_text()=='MATCH · imported claim'
            assert report['results']['chain']['detail'] in page.locator('.card').nth(1).locator('p').inner_text()
        checks.append('six independent cards and verifier detail mapping')
        page.screenshot(path=str(out/'desktop.png'),full_page=True)
        def upload(raw):
            page.locator('#import').set_input_files({'name':'test.json','mimeType':'application/json','buffer':raw.encode()})
            expect(page.locator('#import')).to_have_value('')
        for raw in ['{"x":1,"x":2}','{"x":{"a":1,"\\u0061":2}}','[]','{"x":1e999}','{"x":NaN}','{"a":'+'['*45+'0'+']'*45+'}','{"x":1,}','{}x']:
            upload(raw);assert 'Import rejected:' in page.locator('#message').inner_text()
        upload(' '*1048577);assert 'exceeds' in page.locator('#message').inner_text()
        upload(json.dumps({'items':[None]*20001}));assert 'budget' in page.locator('#message').inner_text()
        checks.append('duplicate/nested/escaped, nonfinite, malformed, byte/node/depth rejection')
        upload(json.dumps(bundle));assert all('MISSING' in x for x in page.locator('.status').all_inner_texts())
        hostile={'source_label':'<img src="https://invalid.example/x" onerror="window.pwned=1">','results':{'artifact':{'status':'verified','reason':'<script>window.pwned=1</script>'}}}
        upload(json.dumps(hostile));assert page.locator('img').count()==0 and page.evaluate('window.pwned === undefined')
        assert 'UNCHECKED' in page.locator('.status').first.inner_text()
        page.locator('.card summary').first.click();assert 'verified' in page.locator('.card pre').first.inner_text()
        checks.append('bare bundle missing, hostile HTML inert, unsupported status unchecked, drilldown')
        page.locator('#reset').click();assert all('MISSING' in x for x in page.locator('.status').all_inner_texts())
        upload(json.dumps(value));page.set_viewport_size({'width':390,'height':844})
        assert page.evaluate('document.body.scrollWidth <= innerWidth')
        for item in page.locator('button,input,summary').all():
            box=item.bounding_box()
            if box:assert box['width']>=44 and box['height']>=44
        page.locator('#reset').focus();assert page.evaluate("document.activeElement.id === 'reset'")
        page.screenshot(path=str(out/'mobile.png'),full_page=True);page.screenshot(path=str(out/'mobile-viewport.png'))
        checks.append('reset, mobile overflow, 44px controls, keyboard focus')
        assert not errors and not remote,(errors,remote)
        checks.append('zero HTTP(S) requests and page errors')
        browser.close()
    result={'checks':checks,'remote_requests':remote,'page_errors':errors,'html':str(html),'visual_review':'separate screenshot inspection required'}
    (out/'browser-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
