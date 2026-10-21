"""Real host Doctor/PluginContext/registry.dispatch acceptance, synthetic homes only.

Run with an installed Hermes dependency environment. Uses version-sensitive Doctor
internals in this development probe, never in the runtime plugin. No live activation.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from hermes_cli.plugin_dev import doctor_plugin, _doctor_runtime
from tools.registry import registry
from smoke_fixtures import cases

DEFAULTS={'bsv_capabilities','bsv_inspect_script','bsv_inspect_transaction','bsv_plan_commitment','bsv_identity_soul','bsv_assurance_artifact'}
SKILLS={'bsv-hermes:inspect-evidence','bsv-hermes:plan-commitment','bsv-hermes:audit-workproducts'}


def exercise(host, names):
    values=cases(); results={}
    assert set(host.manager._plugin_tool_names)==set(names), host.manager._plugin_tool_names
    assert set(host.manager._plugin_skills)==SKILLS
    for item in host.manager._plugin_skills.values():
        assert item['path'].is_file() and item['path'].read_text().startswith('---\n')
        assert str(item['path']).startswith(os.environ['HERMES_HOME'])
    for name in sorted(names):
        entry=registry.get_entry(name,scope=host.manager.scope_key)
        assert entry is not None and entry.toolset=='bsv'
        assert entry.schema['name']==name
        assert entry.schema['parameters']['additionalProperties'] is False
        raw=registry.dispatch(name,values[name],scope=host.manager.scope_key,task_id='synthetic')
        assert type(raw) is str,(name,type(raw))
        result=json.loads(raw)
        assert result['ok'] is True and 'result' in result and 'data' not in result,(name,result)
        for invalid in [None, [], True, '{bad JSON',dict(values[name],unknown='PRIVATE-CANARY')]:
            raw=registry.dispatch(name,invalid,scope=host.manager.scope_key)
            rejected=json.loads(raw)
            assert rejected['ok'] is False and rejected['error']['code']=='invalid_input',(name,rejected)
            assert 'PRIVATE-CANARY' not in raw and len(raw)<350
        results[name]=result
    cap=results['bsv_capabilities']['result']
    assert set(cap['implemented'])==set(names)
    assert results['bsv_plan_commitment']['result']['locking_script_hex']=='006a20e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    assert results['bsv_inspect_transaction']['result']['outputs'][0]['satoshis']==1000
    if 'bsv_int_content' in names:
        bad=dict(values['bsv_int_content'],expected_sha256='0'*64)
        result=json.loads(registry.dispatch('bsv_int_content',bad,scope=host.manager.scope_key))
        assert result['ok'] and result['result']['digest_match'] is False
        bad=dict(values['bsv_int_verify_batch'],commitment='0'*64)
        result=json.loads(registry.dispatch('bsv_int_verify_batch',bad,scope=host.manager.scope_key))
        assert result['ok'] and result['result'] is False
        assert 'proofs' not in results['bsv_int_batch']['result']
        exported=json.loads(registry.dispatch('bsv_int_batch',dict(values['bsv_int_batch'],export_private_proofs=True),scope=host.manager.scope_key))
        assert exported['ok'] and exported['result']['proofs']
        assert results['bsv_assurance_deployment_gate']['result']['evidence_ready'] is True
        assert results['bsv_assurance_approval_intent']['result']['human_consent']=='not_authenticated'
    return {'registered_tools':sorted(names),'registered_skills':sorted(SKILLS),'handler_results':results}


def main():
    path=Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
    # Do not copy ignored development evidence/build trees into Doctor's sandbox.
    with tempfile.TemporaryDirectory(prefix='bsv-smoke-') as temp:
        clean=Path(temp)/'bsv-hermes'
        shutil.copytree(path,clean,ignore=shutil.ignore_patterns('.git','local-verification','build','dist','*.egg-info','__pycache__','*.pyc'))
        report=doctor_plugin(clean)
        assert report.ok and not report.findings,report.format_text()
        with _doctor_runtime(clean) as host:
            assert not host.registered_hooks
            receipt=exercise(host,DEFAULTS)
            host.manager.unload()
            config=Path(os.environ['HERMES_HOME'])/'config.yaml'
            config.write_text(json.dumps({'plugins':{'entries':{'bsv-hermes':{'settings':{'enabled_kits':['identity','assurance','integrations']}}}}}))
            host.manager._load_plugin(host.manifest)
            optional=exercise(host,set(cases()))
            optional['config_readback']=json.loads(config.read_text())['plugins']['entries']['bsv-hermes']['settings']['enabled_kits']==['identity','assurance','integrations']
            assert optional['handler_results']['bsv_capabilities']['result']['enabled_kits']==['assurance','identity','integrations']
            receipt.update(optional=optional,doctor_ok=True,findings=[],dispatch_api='registry.dispatch',
                           isolation='Temporary HOME/config under Doctor; socket connects blocked; no live activation.')
    print(json.dumps(receipt,indent=2))


if __name__=='__main__': main()
