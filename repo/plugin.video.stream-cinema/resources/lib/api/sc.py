# -*- coding: utf-8 -*-

from __future__ import print_function, unicode_literals

import datetime
import json
import time
import traceback
import requests
import xbmcgui

from resources.lib.common.cache import SimpleCache, use_cache
from resources.lib.common.logger import debug, info
from resources.lib.constants import BASE_URL, API_VERSION, SC, ADDON
from resources.lib.kodiutils import get_uuid, get_skin_name, get_setting_as_bool, get_setting_as_int, get_setting, \
    file_put_contents, translate_path, file_exists, file_get_contents
from resources.lib.system import user_agent, Http, SYSTEM_LANG_CODE
from resources.lib.gui.dialog import dok, dinput, dselect, dyesno
from resources.lib.services.Settings import settings

try:
    # Python 3
    from urllib.parse import urlparse, parse_qs
except ImportError:
    # Python 2
    from urlparse import urlparse, parse_qs


class Sc:
    RATING_MAP = {
        "0": 0,
        "1": 6,
        "2": 12,
        "3": 15,
        "4": 18,
    }

    cache = SimpleCache()
    static_cache = {}
    static_cache_type = None


    '''@staticmethod
    def handle_token_error():
        dok("Chybný X-AUTH-TOKEN", "Váš token je neplatný nebo vypršel. Zadejte nový token.")
        new_token = dinput("Zadejte nový X-AUTH-TOKEN:", "")
        if new_token and len(new_token) == 32:
            ADDON.setSetting('system.auth_token', new_token)
            return new_token
        else:
            dok("Chyba", "Neplatný token. Akce zrušena.")
            return None'''
    

    @staticmethod
    def handle_token_error():

        home_win = xbmcgui.Window(10000)
        if home_win.getProperty('sc_token_prompt_shown') == '1':
            dok("Chybný TOKEN", "Váš token je pravděpodobně neplatný. Nový token můžete zadat v nastavení ve správě tokenů.")
            return None
        home_win.setProperty('sc_token_prompt_shown', '1')

        # Load tokens from settings (if any)
        tokens_json = ADDON.getSetting('system.auth_tokens')
        tokens = []
        if tokens_json:
            try:
                tokens = json.loads(tokens_json)
            except Exception:
                tokens = []

        # Get current token from settings
        current_token = ADDON.getSetting('system.auth_token') #for displaying it as active
        options = []
        current_token_index = None

        # Build options, marking the current token
        for idx, t in enumerate(tokens):
            if t == current_token:
                options.append("[B][AKTIVNÍ][/B] {}".format(t)) #mark currently activated token
                current_token_index = idx
            else:
                options.append(t)
        options.append('[+] Přidat nový token')

        # Show selection dialog
        dok('Špatný token','Váš AUTH-TOKEN je neplatný. V následujícím menu vyberte existující token nebo přidejte nový. [CR]Tokeny lze také spravovat v nastavení.')
        selected = dselect(options, "Vyberte TOKEN nebo přidejte nový")
        if selected is None:
            dok("Chyba", "Akce zrušena.")
            return None
        if selected == len(options) - 1:
            # Add new token
            new_token = dinput("Zadejte nový TOKEN:", "")
            if new_token and len(new_token) == 32:
                tokens.append(new_token)
                ADDON.setSetting('system.auth_tokens', json.dumps(tokens))
                ADDON.setSetting('system.auth_token', new_token)
                settings.refresh()
                return new_token
            else:
                dok("Chyba", "Token má špatný formát. Akce zrušena.")
                return None
        else:
            # Use selected token (strip marker if present)
            if options[selected].startswith("[B][AKTIVNÍ][/B]"):
                token = tokens[selected]
            else:
                token = tokens[selected]
            ADDON.setSetting('system.auth_token', token)
            return token
        
    @staticmethod
    def manage_tokens():
        # Load tokens from settings
        tokens_json = ADDON.getSetting('system.auth_tokens')
        tokens = []
        if tokens_json:
            try:
                tokens = json.loads(tokens_json)
            except Exception:
                tokens = []

        current_token = ADDON.getSetting('system.auth_token')
        while True:

            options = []
            for idx, t in enumerate(tokens):
                if t == current_token:
                    options.append("[B][AKTIVNÍ][/B] {}".format(t))
                else:
                    options.append(t)
            options.append("----------------------NÁSTROJE----------------------")
            options.append('[+] Přidat nový token')
            if tokens:
                options.append('[–] Smazat token')
            options.append('[=] Upload tokenu na kra.sk')
            options.append('[Zavřít]')

            selected = dselect(options, "Správa TOKENů")
            if selected is None or options[selected] == '[Zavřít]':
                break
            if options[selected] == '[+] Přidat nový token':
                new_token = dinput("Zadejte nový TOKEN:", "")
                if new_token and len(new_token) == 32:
                    tokens.append(new_token)
                    debug("Token json: {}".format(json.dumps(tokens)))
                    try:
                        ADDON.setSetting('system.auth_tokens', json.dumps(tokens))
                        settings.refresh()
                    except Exception as e:
                        debug("Error saving tokens: {}".format(str(e)))
                    ADDON.setSetting('system.auth_token', new_token)
                    current_token = new_token
                else:
                    dok("Chyba", "Token má špatný formát. Akce zrušena.")
            elif options[selected] == '[–] Smazat token':
                if not tokens:
                    dok("Chyba", "Žádné tokeny k odstranění.")
                    continue
                del_idx = dselect(tokens, "Vyberte token k odstranění")
                if del_idx is not None:
                    del_token = tokens.pop(del_idx)
                    if del_token == current_token:
                        # If deleted token was current, unset
                        ADDON.setSetting('system.auth_token', "")
                        settings.refresh()
                        current_token = ""
                    ADDON.setSetting('system.auth_tokens', json.dumps(tokens))
                    settings.refresh()
            elif options[selected] == '[=] Upload tokenu na kra.sk':
                from resources.lib.api.kraska import Kraska
                # Show warning dialog
                dok("Upozornění", "Upload tokenu na kra.sk je na vlastní nebezpečí. Pokud máte na kra funkční token, udělejte si zálohu! [CR] Aktuální token na kra.sk (v sc.json) bude přepsán.")
                if dyesno("Potvrzení", "Opravdu chcete nahrát aktuální token na kra.sk?","Ano", "Ne") is False:
                    dok("Zrušeno", "Upload tokenu byl zrušen.")
                    continue
                if not current_token or len(current_token) != 32:
                    dok("Chyba", "Není k dispozici platný aktuální token pro upload.")
                    continue
                try:
                    kr = Kraska()
                    kr.upload(current_token, SC.BCK_FILE)
                    dok("Hotovo", "Token byl nahrán na kra.sk jako sc.json.")
                except Exception as e:
                    debug("Chyba, Nepodařilo se nahrát token na kra.sk: {}".format(str(e)))
            else:
                # Select token
                sel_token = tokens[selected] if not options[selected].startswith("[B][AKTIVNÍ][/B]") else current_token
                ADDON.setSetting('system.auth_token', sel_token)
                current_token = sel_token

    @staticmethod
    def get(path, params=None, ttl=None):
        Sc.load_static_cache()
        #debug("Kurva, jdeme na {} s params {}".format(path, params))

        #if path in Sc.static_cache:
        #    ret = Sc.static_cache.get(path, None)
        #    if ret is not None:
        #        debug("{} je zo static cache".format(path))
        #        return ret

        sorted_values, url = Sc.prepare(params, path)
        key = '{}{}{}'.format(ADDON.getAddonInfo('version'), url, sorted_values)
        debug('CALL {} PARAMS {} KEY {}'.format(url, sorted_values, key))
        start = time.time()
        ret = Sc.cache.get(key)
        if ret is None:
            start = time.time()
            try:
                res = Http.get(url, headers=Sc.headers(), params=sorted_values)
                res.raise_for_status()
            except requests.exceptions.HTTPError as e:
                # Check for 404 error (bad token)
                if e.response is not None and e.response.status_code == 404:
                    new_token = Sc.handle_token_error()
                    if new_token:
                        # Retry with new token
                        res = Http.get(url, headers=Sc.headers(), params=sorted_values)
                        res.raise_for_status()
                    else:
                        raise
                else:
                    raise
            ret = res.json()
            debug("Odpoved: {}".format(res.json))
            Sc.save_cache(ret, key, ttl)
        else:
            debug('GET from cache'.format())
            #end = time.time()

        debug('GET took {0:.2f}ms'.format((time.time() - start) * 1000))
        return ret

    @staticmethod
    def prepare(params, path):
        url = BASE_URL + path
        o = urlparse(url)
        query = parse_qs(o.query)
        url = o._replace(query=None).geturl()
        p = Sc.default_params(query)
        # debug('p: {}'.format(p))
        query.update(p)
        if params is not None:
            query.update(params)
        sorted_values = sorted(query.items(), key=lambda val: val[0])
        # debug('sorted: {}'.format(sorted_values))
        return sorted_values, url

    @staticmethod
    def post(path, **kwargs):
        sorted_values, url = Sc.prepare(path=path, params={})
        start = time.time()
        try:
            res = Http.post(url, params=sorted_values, headers=Sc.headers(), **kwargs)
            res.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                new_token = Sc.handle_token_error()
                if new_token:
                    res = Http.post(url, params=sorted_values, headers=Sc.headers(), **kwargs)
                    res.raise_for_status()
                else:
                    raise
            else:
                raise
        ret = res.json()
        debug('POST took {0:.2f}ms'.format((time.time() - start) * 1000))
        return ret

    @staticmethod
    def default_params(query):
        params = {
            'ver': API_VERSION,
            'uid': get_uuid(),
            'skin': get_skin_name(),
            'lang': SYSTEM_LANG_CODE,
        }
        # plugin_url = 'plugin://{}/{}'.format(ADDON_ID, query.params.orig_args if query.params.orig_args else '')
        # try:
        #     kv = KodiViewModeDb()
        #     sort = kv.get_sort(plugin_url)
        # except:
        #     sort = (0, 1)
        # try:
        #     if sort is not None:
        #         params.update({'sm': '{},{}'.format(sort[0], sort[1])})
        # except:
        #     debug('ERR API SORT: {}'.format(traceback.format_exc()))
        #     pass
        parental_control = Sc.parental_control_is_active()
        if get_setting_as_bool('stream.dubed') or (parental_control and get_setting_as_bool('parental.control.dubed')):
            params.update({'dub': 1})

        if not parental_control and get_setting_as_bool('stream.dubed.titles'):
            params.update({'dub': 1, "tit": 1})

        if parental_control:
            params.update({"m": Sc.RATING_MAP.get(get_setting('parental.control.rating'))})

        if get_setting_as_bool('plugin.show.genre'):
            params.update({'gen': 1})

        if 'HDR' not in query:
            params.update({'HDR': 0 if get_setting_as_bool('stream.exclude.hdr') else 1})

        if 'DV' not in query:
            params.update({'DV': 0 if get_setting_as_bool('stream.exclude.dolbyvision') else 1})

        if get_setting_as_bool('plugin.show.old.menu'):
            params.update({'old': 1})

        return params

    @staticmethod
    def parental_control_is_active():
        now = datetime.datetime.now()
        hour_start = get_setting_as_int('parental.control.start')
        hour_now = now.hour
        hour_end = get_setting_as_int('parental.control.end')
        return get_setting_as_bool('parental.control.enabled') and hour_start <= hour_now <= hour_end

    @staticmethod
    def headers(token=True):
        headers = {
            'User-Agent': user_agent(),
            'X-Uuid': get_uuid(),
        }
        if token:
            headers['X-AUTH-TOKEN'] = Sc.get_auth_token()
        return headers

    @staticmethod
    def get_auth_token(force = False):
        token = ''
        if force is False:
            token = ADDON.getSetting('system.auth_token')

        if token == '' or token is None or token == 'None' or token is False:
            from resources.lib.api.kraska import Kraska

            kr = Kraska()
            if kr.get_token():
                found = kr.list_files(filter=SC.BCK_FILE)
                if len(found.get('data', [])) == 1:
                    for f in found.get('data', []):
                        try:
                            url = kr.resolve(f.get('ident'))
                            data = Http.get(url)
                            #dok("Token z kra:".format(data.text)) 
                            debug('Token z kra: {}'.format(data.text))
                            if len(data.text) == 32:
                                token = data.text
                                ADDON.setSetting('system.auth_token', token)
                                return token
                        except Exception as e:
                            debug('error get auth token: {}'.format(traceback.format_exc()))
                else:
                    debug('backup file not found {}'.format(SC.BCK_FILE))

            path = '/auth/token'
            sorted_values, url = Sc.prepare(path=path, params={})
            debug('get auth token from server {}'.format(url))
            debug('get auth token from server params {}'.format(sorted_values))
            res = Http.post(url, params=sorted_values, headers=Sc.headers(False))
            debug('get auth token from server response {}'.format(res.text))
            res.raise_for_status()
            ret = res.json()
            if 'error' in ret:
                debug('error get auth token: {}'.format(ret))
                return None
            if 'token' not in ret:
                debug('error get auth token: {}'.format(ret))
                return None
            token = ret['token']
            ADDON.setSetting('system.auth_token', token)
            try:
                kr.upload(token, SC.BCK_FILE)
            except Exception as e:
                pass
        else:
            debug('auth token from settings {}'.format(token))
        return token

    @staticmethod
    def up_next(id, s, e):
        url = '/upNext/{}/{}/{}'.format(id, s, e)
        try:
            data = Sc.get(url, ttl=3600)
        except:
            data = {'error': 'error'}
        return data

    @staticmethod
    def save_cache(ret, key, ttl=None):
        ttl = 3600 if ttl is None else ttl

        if SC.ITEM_SYSTEM in ret and 'TTL' in ret[SC.ITEM_SYSTEM]:
            ttl = int(ret[SC.ITEM_SYSTEM]['TTL'])

        debug('SAVE TO CACHE {} / {}'.format(ttl, key))
        Sc.cache.set(key, ret, expiration=datetime.timedelta(seconds=ttl))

    @staticmethod
    def static_cache_local_name():
        dpath = ADDON.getAddonInfo('profile')
        return translate_path("{}/{}".format(dpath, Sc.static_cache_filename()))

    @staticmethod
    def static_cache_filename():
        old = 1 if get_setting_as_bool('plugin.show.old.menu') else 0

        return 'menu.{}.json'.format(old)

    @staticmethod
    def download_menu():
        return False
        try:
            url = "{}/../{}".format(BASE_URL, Sc.static_cache_filename())
            info('download menu cache {}'.format(url))
            resp = Http.get(url)
            dfile = Sc.static_cache_local_name()
            file_put_contents(dfile, resp.content)
            Sc.load_static_cache(True)
        except Exception as e:
            debug('error download menu: {}'.format(traceback.format_exc()))

    @staticmethod
    def download_menu_bg():
        from threading import Thread
        worker = Thread(target=Sc.download_menu())
        worker.start()

    @staticmethod
    def load_static_cache():
        Sc.static_cache = {}
        return False
        try:
            if Sc.static_cache != {}:
                debug('uz mame static cache {} == {}'.format(Sc.static_cache_type, Sc.static_cache_filename()))
                return

            if file_exists(Sc.static_cache_local_name()):
                debug('Natahujeme static cache zo suboru')
                Sc.static_cache = json.loads(file_get_contents(Sc.static_cache_local_name()))
                Sc.static_cache_type = Sc.static_cache_filename()
        except Exception as e:
            Sc.static_cache = {}
            debug('error load static menu: {}'.format(traceback.format_exc()))
