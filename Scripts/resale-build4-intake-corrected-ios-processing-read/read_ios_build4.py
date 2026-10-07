#!/usr/bin/env python3
"""One exact iOS build4 processing/group read. No account mutation method exists."""
import argparse,base64,json,os,pathlib,re,time
from datetime import datetime,timezone
from urllib.error import HTTPError,URLError
from urllib.parse import parse_qsl,urlencode,urljoin,urlparse
from urllib.request import Request,build_opener,HTTPRedirectHandler

SOURCE='91ba1e8a6eb1aa18057b11bbab0c0f58b9282ce0'
TEAM='N8K8G6QA36';APP='6819601040';BUNDLE='com.julienbell.ResaleBurrow'
GROUP='e83d545b-4efe-4492-8ccb-6bf41c1008ba';VERSION='0.1.0';BUILD='4'
BRANCH='codex/resale-burrow-build4-intake-corrected-ios-processing-read'
ORIGIN='https://api.appstoreconnect.apple.com'
PROCESSING={'PROCESSING','FAILED','INVALID','VALID'}
INTERNAL={'PROCESSING','PROCESSING_EXCEPTION','MISSING_EXPORT_COMPLIANCE','READY_FOR_BETA_TESTING','IN_BETA_TESTING','EXPIRED','IN_EXPORT_COMPLIANCE_REVIEW'}
APP_QUERY={'fields[apps]':'bundleId'}
BUILD_QUERY={'filter[app]':APP,'filter[version]':BUILD,'filter[preReleaseVersion.version]':VERSION,'filter[preReleaseVersion.platform]':'IOS','include':'preReleaseVersion,app','fields[builds]':'version,uploadedDate,expirationDate,expired,processingState,usesNonExemptEncryption,preReleaseVersion,app','fields[preReleaseVersions]':'version,platform','fields[apps]':'bundleId','limit':'200'}
GROUP_QUERY={'fields[betaGroups]':'isInternalGroup,hasAccessToAllBuilds,app','include':'app','fields[apps]':'bundleId'}
DETAIL_QUERY={'include':'build','fields[buildBetaDetails]':'internalBuildState,build','fields[builds]':'version'}
LINK_QUERY={'limit':'200'}
class Stop(Exception):
    def __init__(self,code,status=None):super().__init__(code);self.code=code;self.status=status
def need(v,code):
    if not v:raise Stop(code)
def ident(v):return isinstance(v,str) and re.fullmatch('[A-Za-z0-9_-]{1,100}',v) is not None
def route(path,q):return path+'?'+urlencode(q)
def resource(v,kind,id=None):
    need(isinstance(v,dict) and v.get('type')==kind and isinstance(v.get('id'),str) and 0<len(v['id'])<=512 and not any(ord(c)<32 or ord(c)==127 for c in v['id']) and (id is None or v['id']==id),'resource_identity_invalid');return v
def link(v,key,kind,id=None):return resource(v.get('relationships',{}).get(key,{}).get('data'),kind,id)
def owned_binding(response, row, relationship, kind, identity, attribute, expected):
    """Apple may omit includes/linkage; every present ownership proof must agree."""
    relationships = row.get('relationships')
    if relationships is None:
        relationships = {}
    need(isinstance(relationships, dict), 'ownership_relationship_shape_invalid')
    linked = False
    if relationship in relationships:
        value = relationships[relationship]
        need(value is None or isinstance(value, dict), 'ownership_relationship_shape_invalid')
        if value is not None and value.get('data') is not None:
            resource(value['data'], kind, identity)
            linked = True
    included = response.get('included') if response.get('included') is not None else []
    need(isinstance(included, list) and all(isinstance(r, dict) for r in included), 'ownership_included_shape_invalid')
    candidates = [r for r in included if isinstance(r, dict) and r.get('type') == kind]
    if candidates:
        need(len(candidates) == 1, 'ownership_included_ambiguous')
        target = resource(candidates[0], kind, identity)
        attrs = target.get('attributes', {})
        need(isinstance(attrs, dict), 'ownership_included_attributes_invalid')
        if attribute in attrs:
            need(attrs[attribute] == expected, 'ownership_included_attribute_contradiction')
    if linked:
        return 'exact_relationship_data'
    if len(candidates) == 1:
        return 'unique_exact_included_resource'
    return None

def stamp(v):
    if v is None:return None
    try:d=datetime.fromisoformat(v.replace('Z','+00:00'));need(d.tzinfo is not None,'timestamp_invalid');return d.astimezone(timezone.utc).isoformat()
    except (ValueError,TypeError,AttributeError):raise Stop('timestamp_invalid') from None
class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args):return None
class ReadClient:
    def __init__(self,token,opener=None):self.token=token;self.opener=opener or build_opener(NoRedirect());self.owned_build=None;self.owned_group=False;self.request_count=0;self.observation=None;self.expected_build_id=None
    def validate(self,path):
        p=urlparse(urljoin(ORIGIN+'/',path));need(p.scheme=='https' and p.netloc=='api.appstoreconnect.apple.com' and not p.username and not p.password and not p.fragment,'origin_outside_scope')
        pairs=parse_qsl(p.query,keep_blank_values=True);need(len(pairs)==len(dict(pairs)),'duplicate_query_parameter');q=dict(pairs);q.pop('cursor',None)
        if p.path=='/v1/apps/'+APP and q==APP_QUERY:return
        if p.path=='/v1/builds' and q==BUILD_QUERY:return
        if p.path=='/v1/betaGroups/'+GROUP and q==GROUP_QUERY:return
        if self.owned_group and p.path=='/v1/betaGroups/'+GROUP+'/app' and q==APP_QUERY:return
        if self.owned_build and p.path=='/v1/builds/'+self.owned_build+'/buildBetaDetail' and q==DETAIL_QUERY:return
        if self.owned_group and p.path in {'/v1/betaGroups/'+GROUP+'/relationships/builds','/v1/betaGroups/'+GROUP+'/relationships/betaTesters'} and q==LINK_QUERY:return
        raise Stop('GET_outside_exact_build4_group_scope')
    def get(self,path):
        self.validate(path);need(self.request_count<20,'request_budget_exhausted');self.request_count+=1
        try:
            with self.opener.open(Request(urljoin(ORIGIN+'/',path),headers={'Authorization':'Bearer '+self.token,'Accept':'application/json'},method='GET'),timeout=30) as r:raw=r.read(2*1024**2+1)
            need(len(raw)<=2*1024**2,'response_too_large');v=json.loads(raw);need(isinstance(v,dict),'response_not_object');return v
        except HTTPError as e:raise Stop('apple_GET_http_error',e.code) from None
        except (URLError,TimeoutError,OSError):raise Stop('apple_GET_unavailable') from None
        except (ValueError,UnicodeError):raise Stop('apple_GET_unreadable') from None
    def collection(self,path):
        anchor=urlparse(urljoin(ORIGIN+'/',path));aq=dict(parse_qsl(anchor.query));aq.pop('cursor',None);seen=set();rows=[];included=[]
        for _ in range(5):
            need(path not in seen,'pagination_cycle');seen.add(path);v=self.get(path);need(isinstance(v.get('data'),list) and isinstance(v.get('included',[]),list),'collection_shape_invalid');rows+=v['data'];included+=v.get('included',[]);need(len(rows)<=1000 and len(included)<=2000,'collection_bound')
            n=v.get('links',{}).get('next')
            if not n:return rows,included
            need(isinstance(n,str),'pagination_invalid');p=urlparse(urljoin(ORIGIN+'/',n));q=dict(parse_qsl(p.query));q.pop('cursor',None);need(p.path==anchor.path and q==aq,'pagination_scope_changed');self.validate(n);path=n
        raise Stop('collection_incomplete')
def exact_ids(rows,kind):
    ids=[resource(v,kind)['id'] for v in rows];need(len(set(ids))==len(ids),'duplicate_relationship_identity');return ids
def read(client,now=None):
    now=now or datetime.now(timezone.utc)
    result={'schema':'ReBurrow-iOS-build4-processing-read-1','observed_at':now.isoformat(),'source_sha':SOURCE,'app_id':APP,'bundle_id':BUNDLE,'platform':'IOS','version':VERSION,'build':'4','build_observed':False,'build_id':None,'processing_state':None,'uses_non_exempt_encryption':None,'internal_build_state':None,'eligible_for_existing_internal_group':False,'group_id':GROUP,'group_observed':False,'tester_count':None,'assigned_build_count':None,'exact_build_assigned':False,'assignment_changed':False,'uploaded':False,'physical_install_verified':False,'account_mutations':0}
    client.observation=result
    app=resource(client.get(route('/v1/apps/'+APP,APP_QUERY)).get('data'),'apps',APP);need(app.get('attributes',{}).get('bundleId')==BUNDLE,'app_bundle_mismatch')
    builds,included=client.collection(route('/v1/builds',BUILD_QUERY));need(len(builds)<=1,'exact_build_ambiguous')
    if builds:
        b=resource(builds[0],'builds');a=b.get('attributes',{});need(ident(b['id']) and a.get('version')==BUILD,'build_number_or_id_mismatch');need(client.expected_build_id is None or b['id']==client.expected_build_id,'pinned_build_id_mismatch')
        owned_binding({'included':included},b,'app','apps',APP,'bundleId',BUNDLE)
        versions=[x for x in included if isinstance(x,dict) and x.get('type')=='preReleaseVersions'];need(len(versions)==1,'prerelease_identity_ambiguous');p=resource(versions[0],'preReleaseVersions');need(p.get('attributes',{}).get('version')==VERSION and p.get('attributes',{}).get('platform')=='IOS','prerelease_version_platform_unverified');owned_binding({'included':included},b,'preReleaseVersion','preReleaseVersions',p['id'],'version',VERSION)
        need(a.get('processingState') in PROCESSING and type(a.get('expired')) is bool and (a.get('usesNonExemptEncryption') is None or type(a['usesNonExemptEncryption']) is bool),'build_status_unknown');client.owned_build=b['id'];expiry=stamp(a.get('expirationDate'));expired=a['expired'] or bool(expiry and datetime.fromisoformat(expiry)<=now)
        result.update(build_observed=True,build_id=b['id'],processing_state=a['processingState'],uses_non_exempt_encryption=a.get('usesNonExemptEncryption'),expired=expired,uploaded_at=stamp(a.get('uploadedDate')),expiration_at=expiry)
        detail=client.get(route('/v1/builds/'+b['id']+'/buildBetaDetail',DETAIL_QUERY));d=resource(detail.get('data'),'buildBetaDetails');result['detail_binding_basis']=owned_binding(detail,d,'build','builds',b['id'],'version',BUILD) or 'exact_owned_parent_endpoint';state=d.get('attributes',{}).get('internalBuildState');need(state in INTERNAL,'internal_testing_state_unknown');result['internal_build_state']=state
        result['eligible_for_existing_internal_group']=a['processingState']=='VALID' and bool(expiry) and not expired and a.get('usesNonExemptEncryption') is False and state in {'READY_FOR_BETA_TESTING','IN_BETA_TESTING'}
    group_response=client.get(route('/v1/betaGroups/'+GROUP,GROUP_QUERY));g=resource(group_response.get('data'),'betaGroups',GROUP);group_basis=owned_binding(group_response,g,'app','apps',APP,'bundleId',BUNDLE);ga=g.get('attributes',{});need(ga.get('isInternalGroup') is True and type(ga.get('hasAccessToAllBuilds')) is bool,'group_internal_identity_unverified');client.owned_group=True
    if group_basis is None:
        direct=resource(client.get(route('/v1/betaGroups/'+GROUP+'/app',APP_QUERY)).get('data'),'apps',APP);need(direct.get('attributes',{}).get('bundleId')==BUNDLE,'group_app_bundle_mismatch');group_basis='exact_group_app_endpoint'
    result['group_app_binding_basis']=group_basis
    members,_=client.collection(route('/v1/betaGroups/'+GROUP+'/relationships/betaTesters',LINK_QUERY));assigned,_=client.collection(route('/v1/betaGroups/'+GROUP+'/relationships/builds',LINK_QUERY));m=exact_ids(members,'betaTesters');a=exact_ids(assigned,'builds')
    result.update(group_observed=True,tester_count=len(m),assigned_build_count=len(a),has_access_to_all_builds=ga['hasAccessToAllBuilds'],exact_build_assigned=bool(result['build_id'] and result['build_id'] in a),request_count=client.request_count,status='complete_read_only')
    result['eligible_for_existing_internal_group']=result['eligible_for_existing_internal_group'] and len(m)==1 and ga['hasAccessToAllBuilds'] is False and len(set(a)-{result['build_id']})==3
    result['limitations']=['Absent build data is not an upload failure or retry permission.','Tester relationship IDs are counted in memory only; no names, emails or identity details are requested or retained.','The exact group was historically Julien Devices; this read does not infer an individual tester identity from the count.','No assignment or encryption declaration change is performed.']
    return result
def scope_gate(scope):
    need(scope.get('dispatchable') is True and scope.get('GET_only') is True and scope.get('store_upload_confirmed') is True,'read_scope_held_until_store_upload')
    for key,value in {'source_sha':SOURCE,'team':TEAM,'app_id':APP,'bundle_id':BUNDLE,'platform':'IOS','version':VERSION,'build':BUILD,'beta_group_id':GROUP}.items():need(scope.get(key)==value,'read_scope_identity_changed')
    need(scope.get('assignment_authorized') is False and scope.get('upload_authorized') is False,'read_scope_cannot_mutate')
    need(re.fullmatch('[0-9a-f]{64}',scope.get('store_upload_receipt_sha256') or '') is not None,'actual_store_upload_evidence_required')
    build_id=scope.get('build_id');need(build_id is None or re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',build_id) is not None,'actual_build_id_or_discovery_required')

def owner_gate(e):
    need(e.get('GITHUB_ACTIONS')=='true' and e.get('GITHUB_REPOSITORY')=='h00l1gvn/LoopFollow' and e.get('GITHUB_ACTOR')=='h00l1gvn' and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and e.get('GITHUB_REF')=='refs/heads/'+BRANCH and e.get('GITHUB_RUN_ATTEMPT')=='1','exact_owner_read_dispatch_required')
def token(e):
    need(e.get('TEAMID')==TEAM and all(e.get(k) for k in ['FASTLANE_KEY_ID','FASTLANE_ISSUER_ID','FASTLANE_KEY']),'existing_CI_credentials_unavailable')
    key=e['FASTLANE_KEY'].replace('\\n','\n').strip()
    if '-----BEGIN PRIVATE KEY-----' not in key:
        try:key=base64.b64decode(key,validate=True).decode()
        except Exception:raise Stop('CI_key_format_unreadable') from None
    try:
        import jwt
        n=int(time.time());return jwt.encode({'iss':e['FASTLANE_ISSUER_ID'],'iat':n,'exp':n+600,'aud':'appstoreconnect-v1'},key,algorithm='ES256',headers={'kid':e['FASTLANE_KEY_ID'],'typ':'JWT'})
    except Exception:raise Stop('CI_token_unavailable') from None
def main():
    p=argparse.ArgumentParser();p.add_argument('--execute-read-only',action='store_true');p.add_argument('--report',type=pathlib.Path,required=True);p.add_argument('--scope',type=pathlib.Path,required=True);a=p.parse_args()
    client=None
    try:need(a.execute_read_only,'explicit_read_flag_required');scope=json.loads(a.scope.read_text());scope_gate(scope);owner_gate(os.environ);client=ReadClient(token(os.environ));client.expected_build_id=scope.get('build_id');r=read(client)
    except Stop as e:
        r={**(client.observation if client and client.observation else {}),'schema':'ReBurrow-iOS-build4-processing-read-1','status':'partial_read_only' if client and client.observation and client.observation.get('build_observed') else 'blocked','observed_at':datetime.now(timezone.utc).isoformat(),'source_sha':SOURCE,'app_id':APP,'version':VERSION,'build':BUILD,'error_code':e.code,'http_status':e.status,'eligible_for_existing_internal_group':False,'account_mutations':0,'uploaded':False,'assignment_changed':False}
    except Exception:r={'status':'blocked','error_code':'read_incomplete','account_mutations':0,'uploaded':False,'assignment_changed':False}
    need(not a.report.exists() and not a.report.is_symlink(),'new_private_report_required');a.report.parent.mkdir(parents=True,exist_ok=True)
    with a.report.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    a.report.chmod(0o600);print(json.dumps({'status':r['status'],'account_mutations':0}));return 0 if r['status']=='complete_read_only' else 2
if __name__=='__main__':raise SystemExit(main())
