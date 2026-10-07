#!/usr/bin/env python3
"""Exact Bryan build5 ad-hoc restore/export. No upload, install or device query.

The shared Store scripts stay unchanged. The reviewed scope carries only CMS
hash membership attestations; raw platform diagnostics remain protected.
"""
from __future__ import annotations
import argparse,base64,datetime,hashlib,json,os,pathlib,plistlib,re,sys,tempfile,zipfile,stat
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import build5_contract as contract
import build5_profile_audit as profiles
import restore_build5_material as material
import validate_resale_export as base
import export_build5_family as store_driver
import resale_apple_audit as audit

SOURCE='79bbd8e2c59fa94c6a3f97942dd0053e5f3086ad'
MATCH=material.MATCH_COMMIT
TOOLING='6e6f97a1b18781c7ffc6cf620f15293c29515fc5'
PHONE=contract.BASE
EXACT={PHONE,PHONE+'.widgets',PHONE+'.watch',PHONE+'.watch.widgets'}
PINS_ALLOWED={'bundle_id','native_profile_id','name','sha256','uuid','profile_type',
 'owner_private_phone_membership_verified_by_exact_cms_hash','native_readback_verified'}
EXISTING_PROFILE_PINS={'com.julienbell.ResaleBurrow': {'bundle_id': 'com.julienbell.ResaleBurrow', 'native_profile_id': '98G99PC3S9', 'name': 'ResaleBurrow Bryan Build2 Ad Hoc 2026-10-06', 'uuid': '89cc16a3-476a-474a-9ab3-fbdbdde31d17', 'sha256': 'eb8d1c019498404d64fea62e783a0eaa5199661a8eef5e0dc5f23682cce36d3f', 'profile_type': 'IOS_APP_ADHOC', 'native_readback_verified': True, 'owner_private_phone_membership_verified_by_exact_cms_hash': True}, 'com.julienbell.ResaleBurrow.watch': {'bundle_id': 'com.julienbell.ResaleBurrow.watch', 'native_profile_id': 'B7MA4B2VH5', 'name': 'ResaleBurrow Watch Bryan Build2 Ad Hoc 2026-10-06', 'uuid': '445034ad-da7e-48af-a726-4d99530aa5c8', 'sha256': 'cb1868f4c96d9b988c71281b4c7eb554cbb3d4477509421f4b270d4b7f85efc6', 'profile_type': 'IOS_APP_ADHOC', 'native_readback_verified': True, 'owner_private_phone_membership_verified_by_exact_cms_hash': True}, 'com.julienbell.ResaleBurrow.widgets': {'bundle_id': 'com.julienbell.ResaleBurrow.widgets', 'native_profile_id': 'M7378SUWRA', 'name': 'ResaleBurrow iOS Widgets Bryan Ad Hoc 2026-10-06', 'uuid': '883d7efb-cabe-4be2-b2a3-43e00886c052', 'sha256': '33386d1ac15b71a00f3ebfa33758c4497fb5fc7632fbf1fee9977849757a902d', 'profile_type': 'IOS_APP_ADHOC', 'native_readback_verified': True, 'owner_private_phone_membership_verified_by_exact_cms_hash': True}, 'com.julienbell.ResaleBurrow.watch.widgets': {'bundle_id': 'com.julienbell.ResaleBurrow.watch.widgets', 'native_profile_id': 'UB47QM5B83', 'name': 'ResaleBurrow Watch Widgets Bryan Ad Hoc 2026-10-06', 'uuid': 'eb951d40-2463-4ecc-a96f-3ccf8c11ac67', 'sha256': '9c21a0178507b2c76edf8cf6888a8df802da39c7044c55cf5854ddabc9040f1b', 'profile_type': 'IOS_APP_ADHOC', 'native_readback_verified': True, 'owner_private_phone_membership_verified_by_exact_cms_hash': True}}
require=base.require
Error=base.ValidationError

def scope_check(scope):
    targets=base.scope_check(scope,'ios')
    require(scope.get('source_sha')==SOURCE and scope.get('tooling_sha')==TOOLING,'bryan_frozen_source_or_tooling_mismatch')
    require(scope.get('source_frozen') is True and scope.get('final_artwork_owner_approved') is True,'bryan_source_artwork_freeze_required')
    require(scope.get('distribution')=='ad-hoc' and scope.get('delivery_lane')=='bryan-ad-hoc'
      and scope.get('profile_material_mode')=='native-adhoc-get-with-immutable-match-certificates'
      and scope.get('match_material_commit')==MATCH,'bryan_distribution_or_material_mode_mismatch')
    rows=scope.get('adhoc_native_profiles')
    require(isinstance(rows,list) and len(rows)==4 and {r.get('bundle_id') for r in rows}==EXACT,'bryan_exact_four_profile_pins_required')
    require(len({r.get('native_profile_id') for r in rows})==4 and len({r.get('uuid') for r in rows})==4,'bryan_duplicate_profile_id_or_uuid')
    pins={}
    for row in rows:
        require(set(row)<=PINS_ALLOWED,'bryan_scope_unexpected_private_fields')
        require(row.get('profile_type')=='IOS_APP_ADHOC' and row.get('native_readback_verified') is True
          and row.get('owner_private_phone_membership_verified_by_exact_cms_hash') is True,'bryan_exact_cms_membership_readback_required')
        require(isinstance(row.get('native_profile_id'),str) and re.fullmatch('[A-Za-z0-9_-]{1,80}',row['native_profile_id'])
          and re.fullmatch('[0-9a-f]{64}',row.get('sha256','')) and re.fullmatch('[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}',row.get('uuid','')),'bryan_profile_pin_invalid')
        require(isinstance(row.get('name'),str) and 0<len(row['name'].encode())<=300 and not re.search('[\x00-\x1f\x7f]',row['name']),'bryan_profile_name_invalid')
        require(row == EXISTING_PROFILE_PINS.get(row['bundle_id']), 'bryan_only_exact_existing_profiles_may_be_reused')
        pins[row['bundle_id']]=row
    return targets,pins

def utc(value):
    require(isinstance(value,datetime.datetime),'bryan_profile_date_missing')
    return value.replace(tzinfo=datetime.timezone.utc) if value.tzinfo is None else value.astimezone(datetime.timezone.utc)

class AdhocProfiles:
    def __init__(self,pins):self.pins=pins;self.selected_phone=None
    def check(self,profile,signature,identifier,now,profile_path):
        return self.check_raw(profile,signature,identifier,now,pathlib.Path(profile_path).read_bytes())
    def check_raw(self,profile,signature,identifier,now,raw):
        pin=self.pins[identifier]
        require(hashlib.sha256(raw).hexdigest()==pin['sha256'] and profile.get('Name')==pin['name']
          and profile.get('UUID')==pin['uuid'],'bryan_embedded_cms_pin_mismatch')
        ent=profile.get('Entitlements',{})
        require(profile.get('TeamIdentifier')==[contract.TEAM] and profile.get('ApplicationIdentifierPrefix')==[contract.TEAM]
          and isinstance(ent,dict) and base.identifier_entitlement(ent,identifier)
          and ent.get('com.apple.developer.team-identifier')==contract.TEAM,'bryan_profile_explicit_identity_mismatch')
        require(ent.get('com.apple.security.application-groups')==[contract.GROUP]
          and ent.get('get-task-allow') is False and profile.get('ProvisionsAllDevices',False) is False,'bryan_release_group_required')
        contract.require_push_grants(identifier,signature.get('entitlements',{}),ent)
        for claims in [ent,signature.get('entitlements',{})]:
            require(not any(k in claims for k in ['com.apple.developer.icloud-services','com.apple.developer.weatherkit','com.apple.developer.carplay-driving-task']),'bryan_unexpected_sensitive_capability')
        created,expiry=utc(profile.get('CreationDate')),utc(profile.get('ExpirationDate'))
        require(created<=now<expiry<=datetime.datetime(2027,9,16,2,46,2,tzinfo=datetime.timezone.utc),'bryan_profile_not_current')
        leaf=signature.get('leaf_der')
        require(isinstance(leaf,bytes) and hashlib.sha256(leaf).hexdigest()==contract.CERT_SHA
          and profile.get('DeveloperCertificates')==[leaf],'bryan_profile_exact_signer_binding_required')
        devices=profile.get('ProvisionedDevices')
        require(isinstance(devices,list) and len(devices)==1 and isinstance(devices[0],str)
          and re.fullmatch('[A-Za-z0-9-]{8,64}',devices[0]),'bryan_single_selected_phone_required')
        if self.selected_phone is None:self.selected_phone=devices[0]
        require(devices[0]==self.selected_phone,'bryan_profiles_selected_phone_mismatch')
        return {'native_profile_id':pin['native_profile_id'],'profile_uuid':pin['uuid'],
          'profile_cms_sha256':pin['sha256'],'certificate_sha256':contract.CERT_SHA,
          'expires_at':expiry.isoformat(),'profile_type':'IOS_APP_ADHOC','same_single_selected_phone_verified':True,
          'private_owner_membership_basis':'reviewed exact CMS hash','raw_hardware_identifier_or_fingerprint_written':False}

def restore(client,apple,scope,output,password,p12_password,now=None,decoder=audit.decode_profile):
    targets,pins=scope_check(scope);now=now or datetime.datetime.now(datetime.timezone.utc)
    require(password and len(p12_password)>=32,'bryan_private_restore_password_missing')
    current=profiles.certificate(apple,now)
    commit=client.get(material.PREFIX+'/git/commits/'+MATCH)
    require(commit.get('sha')==MATCH and re.fullmatch('[0-9a-f]{40}',commit.get('tree',{}).get('sha','')),'bryan_match_commit_changed')
    tree=client.get(material.PREFIX+'/git/trees/'+commit['tree']['sha']+'?recursive=1')
    require(tree.get('truncated') is False and isinstance(tree.get('tree'),list),'bryan_match_tree_incomplete')
    allowed={'certs/distribution/'+profiles.CERT_ID+ext for ext in ['.cer','.p12']};entries={}
    for row in tree['tree']:
        if row.get('path') in allowed:
            require(row['path'] not in entries,'bryan_certificate_tree_ambiguous');entries[row['path']]=row
    require(set(entries)==allowed,'bryan_existing_certificate_material_missing')
    values={key:material.decrypt_entry(client,row,password) for key,row in entries.items()}
    key,cert,info=material.key_pair(values['certs/distribution/'+profiles.CERT_ID+'.p12'],values['certs/distribution/'+profiles.CERT_ID+'.cer'],contract.TEAM,contract.CERT_SHA)
    output=pathlib.Path(output);require(not output.exists() and not output.is_symlink(),'bryan_restore_output_collision');output.mkdir(parents=True,mode=0o700);output.chmod(0o700)
    path=output/'signing_certificate.p12';material.private_bytes(path,material.macos_import_pkcs12(key,cert,p12_password))
    info.update(type='DISTRIBUTION',certificate_id=profiles.CERT_ID,p12_file=str(path.resolve()),p12_file_sha256=base.digest(path))
    rows=[];checker=AdhocProfiles(pins)
    for identifier,target in targets.items():
        pin=pins[identifier];r=apple.get('/v1/profiles/'+pin['native_profile_id']).get('data',{});attrs=r.get('attributes',{})
        require(r.get('id')==pin['native_profile_id'] and attrs.get('name')==pin['name'] and attrs.get('profileType')=='IOS_APP_ADHOC'
          and attrs.get('profileState')=='ACTIVE','bryan_exact_active_native_profile_required')
        content=attrs.get('profileContent','');raw=base64.b64decode(content,validate=True)
        require(0<len(raw)<=2*1024**2 and hashlib.sha256(raw).hexdigest()==pin['sha256'],'bryan_profile_content_changed')
        decoded=decoder(content);require(isinstance(decoded,dict),'bryan_profile_cms_unreadable')
        evidence=checker.check_raw(decoded,{'leaf_der':current,'entitlements':decoded.get('Entitlements',{})},identifier,now,raw)
        dest=output/(pin['uuid']+'.mobileprovision');material.private_bytes(dest,raw)
        rows.append({**pin,**evidence,'target':target['target'],'verified':True,'certificate_sha256':contract.CERT_SHA,'private_profile_file':str(dest.resolve())})
    result={'schema':1,'source_sha':SOURCE,'family':'ios','distribution':'ad-hoc','team':contract.TEAM,'group':contract.GROUP,
      'match_commit':MATCH,'profiles':rows,'signing_certificate':info,'installer_certificate':None,
      'same_single_phone_across_four_profiles':True,'watch_hardware_eligibility_verified':False,
      'network_mutations':False,'phone_queries':0,'keychain_modified':False,'uploaded':False}
    material.private_bytes(output/'restore-manifest.json',(json.dumps(result,indent=2)+'\n').encode());return result

def export_plan(scope,manifest,material_dir,source,work):
    targets,pins=scope_check(scope)
    require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','bryan_reviewed_first_ci_export_required')
    require(manifest.get('schema')==1 and manifest.get('source_sha')==SOURCE and manifest.get('family')=='ios'
      and manifest.get('distribution')=='ad-hoc' and manifest.get('team')==contract.TEAM and manifest.get('group')==contract.GROUP
      and manifest.get('match_commit')==MATCH and manifest.get('installer_certificate') is None,'bryan_restore_identity_mismatch')
    material_dir,source,work=map(lambda p:pathlib.Path(p).resolve(),[material_dir,source,work])
    root=pathlib.Path(os.environ['RUNNER_TEMP']).resolve();workspace=pathlib.Path(os.environ['GITHUB_WORKSPACE']).resolve()
    require(material_dir.is_relative_to(root) and work.is_relative_to(root) and source.is_relative_to(workspace)
      and not work.is_relative_to(source) and not work.is_relative_to(material_dir),'bryan_private_runner_paths_required')
    rows=manifest.get('profiles',[])
    require(len(rows)==4 and {r.get('bundle_id') for r in rows}==EXACT,'bryan_restore_exact_four_required')
    mapping={}
    for row in rows:
        pin=pins[row['bundle_id']]
        require(all(row.get(k)==pin[k] for k in PINS_ALLOWED) and row.get('verified') is True
          and row.get('certificate_sha256')==contract.CERT_SHA and row.get('target')==targets[row['bundle_id']]['target'],'bryan_restore_pin_mismatch')
        path=pathlib.Path(row.get('private_profile_file',''))
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(material_dir) and base.digest(path)==pin['sha256'],'bryan_private_profile_hash_mismatch')
        mapping[row['target']]={'bundle_id':row['bundle_id'],'uuid':row['uuid'],'name':row['name']}
    cert=manifest.get('signing_certificate',{});path=pathlib.Path(cert.get('p12_file',''))
    require(cert.get('verified') is True and cert.get('type')=='DISTRIBUTION' and cert.get('sha256')==contract.CERT_SHA
      and re.fullmatch('[0-9a-f]{40}',cert.get('sha1','')) and path.is_file() and not path.is_symlink()
      and path.resolve().is_relative_to(material_dir) and base.digest(path)==cert.get('p12_file_sha256'),'bryan_private_exact_identity_required')
    return {'source_sha':SOURCE,'family':'ios','distribution':'ad-hoc','mapping':mapping,'certificate':cert,'installer':None}

# The shared Ruby module provides runner-path and exact seven-target project
# checks only. Its Store-only scope_plan is deliberately never bypassed/called.
# The independent Python plan above validates the separate four ad-hoc pins.
RUBY_CONFIG=r'''
require 'json'; require 'xcodeproj'
raise ResaleSigning::GuardError,'pinned_xcodeproj_required' unless Gem.loaded_specs['xcodeproj'].version.to_s=='1.28.1'
checkout,project_path,scope_path,plan_path,export_path,report_path=ARGV
scope=JSON.parse(File.read(scope_path));plan=JSON.parse(File.read(plan_path))
ResaleSigning.require_guard(plan['source_sha']==scope['source_sha'] && plan['family']=='ios' && plan['distribution']=='ad-hoc' && plan['installer'].nil?,'adhoc_plan_identity_mismatch')
ResaleSigning.require_guard(plan['certificate']['sha256']==ResaleSigning::APPROVED_CERT && ResaleSigning.fingerprint(plan['certificate']['sha1'],40),'adhoc_certificate_mismatch')
wanted=ResaleSigning::EXACT.select{|_,values|values[1]=='ios'}.transform_values{|values|values[0]}
ResaleSigning.require_guard(plan['mapping'].keys.sort==wanted.keys.sort && plan['mapping'].all?{|name,row|row['bundle_id']==wanted[name]},'adhoc_exact_four_mapping_required')
options={checkout:checkout,project:project_path,scope:scope_path,manifest:plan_path,export_options:export_path,report:report_path}
ResaleSigning.runner_paths!(options,scope)
root=File.realpath(ENV.fetch('RUNNER_TEMP'))
[export_path,report_path].each{|path|parent=File.realpath(File.dirname(path));ResaleSigning.require_guard(parent.start_with?(root+'/') && !File.symlink?(path) && !File.exist?(path),'adhoc_private_output_collision')}
project=Xcodeproj::Project.open(project_path);ResaleSigning.project_preflight(project,plan)
other=project.targets.reject{|t|plan['mapping'].key?(t.name)};before=JSON.generate(other.map{|t|[t.name,t.build_configurations.map{|c|[c.name,c.build_settings]}]})
project.targets.each do |target|
 next unless plan['mapping'].key?(target.name)
 row=plan['mapping'][target.name]
 target.build_configurations.each{|config|config.build_settings.merge!('CODE_SIGN_STYLE'=>'Manual','DEVELOPMENT_TEAM'=>ResaleSigning::TEAM,'CODE_SIGN_IDENTITY'=>plan['certificate']['sha1'],'PROVISIONING_PROFILE'=>row['uuid'],'PROVISIONING_PROFILE_SPECIFIER'=>row['name'])}
end
ResaleSigning.require_guard(before==JSON.generate(other.map{|t|[t.name,t.build_configurations.map{|c|[c.name,c.build_settings]}]}),'unselected_targets_changed')
project.save
export={'method'=>'release-testing','destination'=>'export','signingStyle'=>'manual','teamID'=>ResaleSigning::TEAM,'signingCertificate'=>plan['certificate']['sha1'],'provisioningProfiles'=>plan['mapping'].values.to_h{|p|[p['bundle_id'],p['uuid']]},'manageAppVersionAndBuildNumber'=>false,'uploadSymbols'=>false}
Xcodeproj::Plist.write_to_path(export,export_path);File.chmod(0600,export_path)
ResaleSigning.private_write(report_path,JSON.pretty_generate({'family'=>'ios','distribution'=>'ad-hoc','configured_bundle_ids'=>wanted.values,'canonical_source_modified'=>false,'uploaded'=>false})+"\n")
'''

def validate_artifacts(archive,export,scope,report,now=None,runner=None):
    targets,pins=scope_check(scope);now=now or datetime.datetime.now(datetime.timezone.utc)
    runner=runner or base.Runner(pathlib.Path(report).parent/'adhoc-validation-private');checker=AdhocProfiles(pins)
    archive,export=pathlib.Path(archive),pathlib.Path(export)
    require(archive.is_dir() and archive.suffix=='.xcarchive' and not archive.is_symlink(),'bryan_archive_required')
    props=base.load_plist(archive/'Info.plist').get('ApplicationProperties',{})
    require(props.get('CFBundleIdentifier')==PHONE,'bryan_archive_primary_mismatch')
    app_path=contract.safe_relative(props.get('ApplicationPath'));primary=archive/'Products'/str(app_path)
    require(primary.resolve().is_relative_to((archive/'Products/Applications').resolve()) and list((archive/'Products/Applications').glob('*.app'))==[primary]
      and {p.name for p in (archive/'Products').iterdir()}=={'Applications'},'bryan_archive_single_app_required')
    archive_rows=base.bundle_set(primary,targets,runner,now,profile_validator=checker.check)
    require(export.is_dir() and not export.is_symlink(),'bryan_export_directory_required')
    ipas=list(export.glob('*.ipa'));require(len(ipas)==1 and ipas[0].is_file() and not ipas[0].is_symlink(),'bryan_exact_one_ipa_required');ipa=ipas[0]
    with zipfile.ZipFile(ipa) as z:
        entries=z.infolist();names=[r.filename for r in entries]
        require(0<len(entries)<=100000 and len(set(names))==len(names),'bryan_duplicate_or_unbounded_ipa')
        require(sum(e.file_size for e in entries)<=2*1024**3,'bryan_ipa_size_bound')
        for entry in entries:
            p=pathlib.PurePosixPath(entry.filename)
            require(not p.is_absolute() and '..' not in p.parts and '\\' not in entry.filename and not stat.S_ISLNK(entry.external_attr>>16),'bryan_unsafe_ipa_member')
    with tempfile.TemporaryDirectory(prefix='bryan-adhoc-validation-',dir=pathlib.Path(report).parent) as tmp:
        dest=pathlib.Path(tmp)/'expanded';dest.mkdir(mode=0o700)
        expanded=base.extract_ipa(ipa,dest)
        export_rows=base.bundle_set(expanded,targets,runner,now,profile_validator=checker.check)
    result={'status':'passed','family':'ios','distribution':'ad-hoc','source_sha_basis':SOURCE,'version':'0.1.0','build':'5',
      'archive_bundles':archive_rows,'export_bundles':export_rows,'exact_bundle_count':4,'export_artifact_sha256':base.digest(ipa),
      'same_single_selected_phone_verified':True,'watch_hardware_eligibility_verified':False,'raw_hardware_identifier_or_fingerprint_written':False,
      'signed_local_artifacts_verified':True,'phone_queries':0,'uploaded':False,'installed':False}
    base.private_write(report,json.dumps(result,indent=2)+'\n');return result

def build(scope,scope_file,manifest,material_dir,source,work,password_file,gemfile,review,source_manifest):
    contract.validate_freeze(review,source_manifest,source)
    plan=export_plan(scope,manifest,material_dir,source,work)
    source,work,material_dir=map(lambda p:pathlib.Path(p).resolve(),[source,work,material_dir]);runner=store_driver.PrivateRunner(work)
    require(runner.run(['git','-C',source,'rev-parse','HEAD'],'source-sha').decode().strip()==SOURCE
      and not runner.run(['git','-C',source,'status','--porcelain'],'source-clean'),'bryan_clean_frozen_source_required')
    require(re.search('^Xcode 26[.]2$',runner.run(['/usr/bin/xcodebuild','-version'],'xcode-version').decode(),re.M),'bryan_xcode_26_2_required')
    require(pathlib.Path(gemfile).is_file(),'bryan_pinned_gemfile_missing');os.environ['BUNDLE_GEMFILE']=str(pathlib.Path(gemfile).resolve())
    password_file=pathlib.Path(password_file);require(password_file.is_file() and not password_file.is_symlink() and password_file.stat().st_mode&0o077==0,'bryan_private_password_required')
    password=password_file.read_text().strip();require(len(password)>=32,'bryan_private_password_too_short')
    keychain=material_dir/'resale-bryan-ephemeral.keychain-db';keychain_password=__import__('secrets').token_urlsafe(48);original=None;created=False;installed=[];cleanup=[]
    try:
        original=__import__('shlex').split(runner.run(['/usr/bin/security','list-keychains','-d','user'],'original-search-list').decode())
        runner.run(['/usr/bin/security','create-keychain','-p',keychain_password,keychain],'keychain-create');created=True
        runner.run(['/usr/bin/security','set-keychain-settings','-lut','21600',keychain],'keychain-timeout')
        runner.run(['/usr/bin/security','unlock-keychain','-p',keychain_password,keychain],'keychain-unlock')
        runner.run(['/usr/bin/security','list-keychains','-d','user','-s',keychain,*original],'keychain-search-list')
        runner.run(['/usr/bin/security','import',manifest['signing_certificate']['p12_file'],'-k',keychain,'-P',password,'-T','/usr/bin/codesign','-T','/usr/bin/security'],'import-signing-certificate')
        runner.run(['/usr/bin/security','set-key-partition-list','-S','apple-tool:,apple:,codesign:','-s','-k',keychain_password,keychain],'keychain-partition')
        for row in manifest['profiles']:
            raw=pathlib.Path(row['private_profile_file']).read_bytes()
            for folder in [pathlib.Path.home()/'Library/MobileDevice/Provisioning Profiles',pathlib.Path.home()/'Library/Developer/Xcode/UserData/Provisioning Profiles']:
                folder.mkdir(parents=True,exist_ok=True);dest=folder/(row['uuid']+'.mobileprovision')
                if dest.exists():require(not dest.is_symlink() and dest.read_bytes()==raw,'bryan_runner_profile_collision')
                else:material.private_bytes(dest,raw);installed.append(dest)
        plan_path=work/'manual-plan.json';material.private_bytes(plan_path,(json.dumps(plan)+'\n').encode())
        shared=pathlib.Path(__file__).resolve().parent
        project=source/'apple/ResaleBurrow.xcodeproj';options=work/'ExportOptions.plist'
        runner.run(['bundle','exec','ruby','-r',shared/'configure_build5_signing.rb','-e',RUBY_CONFIG,'--',source,project,scope_file,plan_path,options,work/'manual-signing-config.json'],'manual-configure',cwd=source,timeout=120)
        archive=work/'ResaleBurrow.xcarchive';export=work/'export'
        runner.run(['/usr/bin/xcodebuild','-project',project,'-scheme','ResaleBurrowIOS','-configuration','Release','-destination','generic/platform=iOS','-archivePath',archive,'archive'],'archive',cwd=source,timeout=3600)
        runner.run(['/usr/bin/xcodebuild','-exportArchive','-archivePath',archive,'-exportPath',export,'-exportOptionsPlist',options],'export',cwd=source,timeout=1200)
        validation=validate_artifacts(archive,export,scope,work/'signed-validation.json')
        ipa=next(export.glob('*.ipa'));final=export/'ResaleBurrow-Bryan-build5.ipa'
        if ipa!=final:require(not final.exists(),'bryan_final_ipa_collision');ipa.rename(final)
        provenance={'schema':1,'source_sha':SOURCE,'tooling_sha':TOOLING,'delivery_sha':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),
          'family':'ios','distribution':'ad-hoc','delivery_lane':'bryan-ad-hoc','version':'0.1.0','build':'5','team':contract.TEAM,'group':contract.GROUP,
          'exact_bundle_ids':sorted(EXACT),'archived':True,'exported':True,'signed_validation_passed':True,'ipa_sha256':validation['export_artifact_sha256'],
          'phone_queries':0,'installed':False,'uploaded':False,'watch_hardware_eligibility_verified':False,'profile_or_certificate_created_by_export':False}
        base.private_write(work/'export-provenance.json',json.dumps(provenance,indent=2)+'\n')
    finally:
        if original is not None:
            try:runner.run(['/usr/bin/security','list-keychains','-d','user','-s',*original],'restore-search-list')
            except Exception:cleanup.append('search_list_restore_failed')
        if created:
            try:runner.run(['/usr/bin/security','delete-keychain',keychain],'keychain-delete')
            except Exception:cleanup.append('ephemeral_keychain_delete_failed')
        for path in installed:
            try:path.unlink()
            except FileNotFoundError:pass
            except OSError:cleanup.append('new_profile_cleanup_failed')
        base.private_write(work/'runner-step-receipt.json',json.dumps({'steps':runner.steps,'canonical_source_untouched':True,'runner_only_project_signing_configuration':True,
          'ephemeral_cleanup_verified':not cleanup,'cleanup_failures':cleanup,'phone_queries':0,'uploaded':False,'installed':False},indent=2)+'\n')
        require(not cleanup,'bryan_ephemeral_cleanup_incomplete')

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=['restore','export'],required=True)
    p.add_argument('--scope',type=pathlib.Path,required=True);p.add_argument('--material-dir',type=pathlib.Path,required=True)
    p.add_argument('--p12-password-file',type=pathlib.Path,required=True);p.add_argument('--source-dir',type=pathlib.Path)
    p.add_argument('--work-dir',type=pathlib.Path);p.add_argument('--bundle-gemfile',type=pathlib.Path)
    p.add_argument('--release-review',type=pathlib.Path);p.add_argument('--source-manifest',type=pathlib.Path);a=p.parse_args(argv)
    try:
        require(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('GITHUB_RUN_ATTEMPT')=='1','bryan_reviewed_first_ci_required')
        require(a.material_dir.resolve().is_relative_to(pathlib.Path(os.environ['RUNNER_TEMP']).resolve()),'bryan_material_not_private_runner')
        scope=json.loads(a.scope.read_text());scope_check(scope)
        if a.mode=='restore':
            require(os.environ.get('TEAMID')==contract.TEAM,'bryan_team_environment_mismatch')
            require(a.p12_password_file.is_file() and not a.p12_password_file.is_symlink() and a.p12_password_file.stat().st_mode&0o077==0,'bryan_private_password_required')
            # MaterialReadClient authorizes exact profiles from native_profiles;
            # supply only this separate reviewed four-profile allowlist.
            get_scope={**scope,'native_profiles':scope['adhoc_native_profiles']}
            restore(material.CertificateReadClient(os.environ['GH_PAT']),material.ProfileReadClient(audit.apple_token(os.environ),get_scope),scope,a.material_dir,
              os.environ['MATCH_PASSWORD'],a.p12_password_file.read_text().strip())
        else:
            require(all([a.source_dir,a.work_dir,a.bundle_gemfile,a.release_review,a.source_manifest]),'bryan_export_arguments_missing')
            build(scope,a.scope.resolve(),json.loads((a.material_dir/'restore-manifest.json').read_text()),a.material_dir,a.source_dir,a.work_dir,a.p12_password_file,
              a.bundle_gemfile,json.loads(a.release_review.read_text()),json.loads(a.source_manifest.read_text()))
        print(json.dumps({'status':'completed','mode':a.mode,'phone_queries':0,'uploaded':False,'installed':False}));return 0
    except (Error,contract.GateError,audit.AuditError) as e:print(json.dumps({'status':'stopped','code':str(e),'phone_queries':0,'uploaded':False}));return 1
    except Exception:print(json.dumps({'status':'stopped','code':'bryan_private_operation_failed','phone_queries':0,'uploaded':False}));return 1

if __name__=='__main__':raise SystemExit(main())
