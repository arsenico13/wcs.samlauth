from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.errors import OneLogin_Saml2_Error
from plone import api
from plone.protect.interfaces import IDisableCSRFProtection
from Products.Five.browser import BrowserView
from urllib.parse import quote
from urllib.parse import urlparse
from urllib.parse import urlunparse
from zExceptions import BadRequest
from zope.interface import alsoProvides
import logging


LOGGER = logging.getLogger(__name__)
SAML_AUTHN_REQUEST_COOKIE_NAME = '__saml'
LOGIN_PATH_SUFFIX = '/login'


def normalize_return_url(url):
    """Return the target URL a user should land on after login."""
    if not url:
        return None

    parsed = urlparse(url)
    path = parsed.path.rstrip('/')
    if path.endswith(LOGIN_PATH_SUFFIX):
        path = path[:-len(LOGIN_PATH_SUFFIX)] or '/'
        url = urlunparse(parsed._replace(path=path))
    return url


def get_request_return_url(request):
    return normalize_return_url(
        request.get('came_from', None) or request.get('return_url', None)
    )


def is_allowed_redirect_url(url, allowed_hosts):
    """Validate redirect targets without rejecting root-relative URLs."""
    parsed = urlparse(url)
    if not parsed.netloc:
        return parsed.scheme == '' and url.startswith('/') and not url.startswith('//')
    return parsed.scheme in ('http', 'https') and parsed.netloc in allowed_hosts


class BaseSamlView(BrowserView):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.saml_request = self._prepare_request()
        self.settings = self.context.load_settings()
        self._update_settings()

    def _prepare_request(self):
        url = urlparse(self.request.URL)
        request = {
            'https': 'on' if url.scheme == 'https' else 'off',
            'http_host': url.netloc,
            'script_name': url.path,
            'get_data': self.request.form.copy(),
            'post_data': self.request.form.copy()
        }
        # if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        if self.context.getProperty('adfs_as_idp'):
            request['lowercase_urlencoding'] = True
        return request

    def _update_settings(self):
        """Update SP settings with dynamic values"""
        plugin_url = self.context.absolute_url()
        sp = self.settings['sp']
        sp['entityId'] = plugin_url + '/metadata'
        sp['assertionConsumerService']['url'] = plugin_url + '/acs'
        sp['singleLogoutService']['url'] = plugin_url + '/slo'


class LoginView(BaseSamlView):
    def __call__(self):
        try:
            auth = OneLogin_Saml2_Auth(self.saml_request, self.settings)
        except OneLogin_Saml2_Error as error:
            LOGGER.error(str(error))
            self.request.response.setHeader('X-Theme-Disabled', '1')
            self.request.response.setHeader('Content-Type', 'text/plain')
            self.request.response.setStatus(400)
            if self.settings['debug']:
                return f'SAML SP configuration error: {str(error)}'
            return 'SAML SP configuration not valid, please check logs'

        return_url = get_request_return_url(self.request)
        if not return_url:
            return_url = api.portal.get().absolute_url()
        login_url = auth.login(return_to=return_url)

        if auth.get_last_request_id() and self.context.getProperty('validate_authn_request', False):
            self.request.response.setCookie(
                SAML_AUTHN_REQUEST_COOKIE_NAME,
                auth.get_last_request_id()
            )
        return self.request.RESPONSE.redirect(login_url)


class CallbackView(BaseSamlView):
    def __call__(self):
        alsoProvides(self.request, IDisableCSRFProtection)
        auth = OneLogin_Saml2_Auth(self.saml_request, self.settings)
        request_id = None

        if SAML_AUTHN_REQUEST_COOKIE_NAME in self.request:
            request_id = self.request[SAML_AUTHN_REQUEST_COOKIE_NAME]

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        if len(errors) != 0 and not auth.is_authenticated():
            LOGGER.error(errors)
            LOGGER.error(auth.get_last_error_reason())
            raise BadRequest

        if request_id:
            self.request.response.expireCookie(SAML_AUTHN_REQUEST_COOKIE_NAME)

        self.context.remember_identity(auth)

        return self.request.response.redirect(self.get_redirect_url())

    def get_redirect_url(self):
        url = api.portal.get().absolute_url()
        if 'RelayState' in self.request.form:
            relay_state = normalize_return_url(self.request.form['RelayState'])
            allowed_hosts = [self.saml_request['http_host']]
            allowed_hosts.extend(
                list(self.context.getProperty('allowed_redirect_hosts', ()))
            )
            if relay_state and is_allowed_redirect_url(relay_state, allowed_hosts):
                url = relay_state

        create_api_session = self.context.getProperty("create_api_session")
        include_api_token = self.context.getProperty("include_api_token_in_redirect")
        if include_api_token and create_api_session:
            token = self.request.RESPONSE.cookies.get('auth_token', None)
            if token:
                url += f'?auth_token={token["value"]}'
        return url


class IdpLogoutView(BaseSamlView):
    def __call__(self):
        auth = OneLogin_Saml2_Auth(self.saml_request, self.settings)

        def _logout():
            mt = api.portal.get_tool('portal_membership')
            mt.logoutUser(self.request)
            # Handle JWT token logout

        auth.process_slo(delete_session_cb=_logout)
        return self.request.RESPONSE.redirect(api.portal.get().absolute_url() + '/logged-out')


class LogoutView(BaseSamlView):
    def __call__(self):
        auth = OneLogin_Saml2_Auth(self.saml_request, self.settings)
        logout_url = auth.logout(return_to=api.portal.get().absolute_url())
        return self.request.RESPONSE.redirect(logout_url)


class MetadataView(BaseSamlView):
    def __call__(self):
        self.request.response.setHeader('X-Theme-Disabled', '1')
        auth = OneLogin_Saml2_Auth(self.saml_request, self.settings)
        saml_settings = auth.get_settings()
        metadata = saml_settings.get_sp_metadata()
        errors = saml_settings.validate_metadata(metadata)

        if len(errors) == 0:
            self.request.response.setHeader('Content-Type', 'application/xml')
            return metadata
        else:
            return "Error found on Metadata: %s" % (', '.join(errors))


class RequireLoginView(BrowserView):
    """Our version of the require-login view from Plone.

    Our challenge plugin redirects here.
    Note that the plugin has no way of knowing if you are authenticated:
    its code is called before this is known.
    I think.
    """

    def __call__(self):
        if api.user.is_anonymous():
            # context is our PAS plugin
            url = self.context.absolute_url() + '/sls'
            return_url = get_request_return_url(self.request)
            if return_url:
                url += f'?came_from={quote(return_url)}'
        else:
            url = api.portal.get().absolute_url()
            url += '/insufficient-privileges'

        self.request.response.redirect(url)
