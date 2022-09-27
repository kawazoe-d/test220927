import io
import datetime
import urllib.parse
import xml.etree.ElementTree as ET

from django.shortcuts import render, redirect
from config.settings import BASE_DIR
from django.conf import settings
from django.core.cache import cache
from django.utils.crypto import get_random_string
from django.utils.xmlutils import SimplerXMLGenerator
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.http import (HttpResponse, HttpResponseRedirect)

from onelogin.saml2.utils import OneLogin_Saml2_Utils

import environ
env = environ.Env()
env.read_env('.env')

# AzureAD公開鍵
pub_key = env('PUBLIC_KEY')

def init_request_xml():
    """
    SAML認証要求生成
    """
    # リクエスト用ユニークIDの生成
    request_id = get_saml_id(34)

    # IssueInstant用の時刻を取得
    time = datetime.datetime.now().isoformat() + 'Z'

    xml_string = generate_saml_request_xml(request_id, time)

    # XMLを文字列からElementに直接パース
    root = ET.fromstring(xml_string)

    # IDをキャッシュにセット
    cache_name = 'in_request_to.cache' + request_id
    cache.set(cache_name, request_id, 30)

    ret = ET.tostring(root)
    retdeco = ret.decode()
    b64encoded = OneLogin_Saml2_Utils.deflate_and_base64_encode(retdeco)
    urlencoded = urllib.parse.quote(b64encoded)
    return urlencoded

def generate_saml_request_xml(id, time):
    """
    SAMLリクエスト用のXMLを生成
    StringIODEを文字列にして返す
    """
    stream = io.StringIO()

    xml = SimplerXMLGenerator(stream, settings.DEFAULT_CHARSET)
    xml.startDocument()
    xml.startElement('md:AuthnRequest', {
        'xmlns': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'ID': id,
        'Version': '2.0',
        'IssueInstant': time,
        'xmlns:md': 'urn:oasis:names:tc:SAML:2.0:protocol',
    })
    xml.addQuickElement('Issuer', 'http://localhost:8000/metadata/', {
        'xmlns': 'urn:oasis:names:tc:SAML:2.0:assertion',
    })
    xml.endElement('md:AuthnRequest')

    return stream.getvalue()

def get_saml_id(num):
    """
    SAMLIDの設定
    数字以外から開始
    """
    tmp = get_random_string(num)
    while is_begin_with_number(tmp):
        tmp = get_random_string(num)
    return tmp

def is_begin_with_number(num):
    """
    数字から始まっているか確認
    """
    if num[0:1].isdigit():
        return True
    return False

def saml_auth_errors(in_response_to):
    # レスポンスのIDがリクエストのIDと同じか、キャッシュで確認
    in_request_to = cache.get('in_request_to.cache' + in_response_to)
    if in_request_to != in_response_to:
        return "認証エラーが発生しました。"

def prepare_django_request(request):
    """
    requestを成形する
    """
    result = {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy()
    }
    return result

def index(request):
    if request.user.is_authenticated:
        user = request.user

        params = {
            'user': user
        }

        return render(request, 'user.html', params)

    """
    TOPページ表示
    TOPページをレンダリングする
    """
    req = prepare_django_request(request)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    # SAML認証要求の生成
    xml = init_request_xml()

    # AADログインURL
    azure_ad_url = env('AZURE_AD_URL')

    # login.microsoftonline.comへSAML認証要求をリダイレクト
    return HttpResponseRedirect(f"https://login.microsoftonline.com/{azure_ad_url}/saml2?SAMLRequest={xml}&RelayState=http%3A%2F%2Flocalhost%3A8000%2F")

@csrf_exempt
def acs(request):
    request_id = None
    # レスポンスからXMLをデコード
    decode_body = request.body.decode()
    urldecord_body = urllib.parse.unquote(decode_body)
    encoded_xml = urldecord_body.replace('SAMLResponse=', '').replace('&RelayState=http://localhost:8000/', '')
    decode_xml = OneLogin_Saml2_Utils.b64decode(encoded_xml).decode()
    root = ET.fromstring(decode_xml)

    # レスポンスのSAMLID
    in_response_to = root.attrib["InResponseTo"]

    errors = saml_auth_errors(in_response_to)
    if not errors:
        print('success')
        paint_logout = True
        assertion = None
        for element in root:
            if "Assertion" in element.tag:
                assertion = element
        subject = None
        attribute_statement = None
        for element in assertion:
            if "Subject" in element.tag:
                subject = element
            elif "AttributeStatement" in element.tag:
                attribute_statement = element
        integration_id = ""
        for element in subject:
            if "NameID" in element.tag:
                integration_id = element.text
        attribute = {}
        for element in attribute_statement:
            if "Attribute" in element.tag:
                name = element.attrib["Name"]
                attribute[name] = [c_element.text for c_element in element][0]
        attributes = {
            'displayname' : attribute["http://schemas.microsoft.com/identity/claims/displayname"],
            'emailaddress' : attribute["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"],
        }
        email = attributes['emailaddress']
        user = authenticate(request, username=email)
        if user is not None:
            login(request, user)
    params = {'errors': errors, 'attributes': attributes, 'paint_logout': paint_logout}
    # return render(request, 'index.html', params)
    return redirect('/')

def metadata(request):
    # validUntil用の時刻を取得
    time = datetime.datetime.now().isoformat() + 'Z'

    response = HttpResponse(content_type='application/xml')
    handler = SimplerXMLGenerator(response, settings.DEFAULT_CHARSET)
    handler.startDocument()
    handler.startElement('md:EntityDescriptor', {
        'xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata',
        'validUntil': time,
        'cacheDuration':'PT604800S',
        'entityID':'http://localhost:8000/metadata/',
    })
    handler.startElement('md:SPSSODescriptor', {
        'AuthnRequestsSigned':'false',
        'WantAssertionsSigned':'false',
        'protocolSupportEnumeration':'urn:oasis:names:tc:SAML:2.0:protocol',
    })
    handler.startElement('md:SingleLogoutService', {
        'Binding':'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'Location':'http://localhost:8000/?sls',
    })
    handler.endElement('md:SingleLogoutService')
    handler.addQuickElement('md:NameIDFormat', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')
    handler.startElement('md:AssertionConsumerService', {
        'Binding':'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
        'Location':'http://localhost:8000/?acs',
        'index':'1',
    })
    handler.endElement('md:AssertionConsumerService')
    handler.endElement('md:SPSSODescriptor')
    handler.endElement('md:EntityDescriptor')
    
    return response

@login_required
def user(request):
    user = request.user

    params = {
        'user': user
    }

    return render(request, 'user.html', params)