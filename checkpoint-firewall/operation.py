""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import ipaddress, json, time, requests, math
from connectors.core.connector import get_logger, ConnectorError
from .constants import rest_api

logger = get_logger('checkpoint-firewall')


def get_input(params, key, type):
    try:
        ret_val = params.get(key, None)
        if ret_val:
            if isinstance(ret_val, type):
                return ret_val
            else:
                logger.info("Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type is: {1}".format(str(key), str(type)))
                raise ConnectorError("Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter Type is: {1}".format(str(key), str(type)))
        else:
            if ret_val == 0 or ret_val == [] or ret_val == {}:
                return ret_val
            return None
    except Exception as Err:
        raise ConnectorError(Err)


class CheckPointOps:
    def __init__(self, config):
        self.verify_ssl = config.get("verify_ssl", None)
        address = get_input(config, "address", str)
        port = get_input(config, "port", int)
        server_url = '{0}:{1}'.format(address, port)
        self.username = get_input(config, "username", str)
        self.password = get_input(config, "password", str)
        self.domain = config.get("domain")
        self.ip_block_policy = get_input(config, "ip_block_policy", str)
        self.url_block_policy = get_input(config, "url_block_policy", str)
        self.app_block_policy = get_input(config, "app_block_policy", str)
        if server_url[:7] != 'http://' and server_url[:8] != 'https://':
            server_url = 'https://{}'.format(str(server_url))
        self.server_url = server_url
        self.session = None
        self.status = {}
        self.install_policy = config.get("install_policy", True)

    def __check_show_task(self, task_id):
        try:
            payload = {'task-id': task_id}
            url = '{0}{1}'.format(self.server_url, rest_api["SHOW_TASK"])
            time_out = 300
            time_interval = 10
            while True:
                status = self.__get_request(url, payload=payload)
                if len(status["tasks"]) != 0 and status["tasks"][0]["status"] == "succeeded":
                    return True
                elif status["tasks"][0]["status"] == "failed" or time_out == 0:
                    return False
                else:
                    time_out = time_out - time_interval
                    time.sleep(time_interval)
        except Exception as Err:
            raise ConnectorError(Err)

    def __publish_install_policy(self):
        try:
            publish_status, publish_response = self.__publish()
            if publish_status:
                if self.install_policy:
                    install_policy_status, install_policy_response = self.__install_policy()
                    if install_policy_status:
                        discard_session_response = self.discard_session({}, {})
                        self.status.update({"discard_session_response": discard_session_response})
                        return self.status
                    else:
                        self.discard_session({}, {})
                        logger.exception("Fail to Install Policy Error is:{}".format(install_policy_response))
                        raise ConnectorError("Fail to Install Policy Error is:{}".format(install_policy_response))
            else:
                logger.exception("Fail To Publish Changes Function Time out "
                                 "Error Response is : {}".format(publish_response))
                raise ConnectorError("Fail To Publish changes Error is : {}".format(publish_response))
        except Exception as Err:
            raise ConnectorError(Err)

    def __get_app_group_details(self):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["SHOW_APP_GROUP"])
            if self.app_block_policy:
                payload = {'name': self.app_block_policy}
            else:
                logger.exception("Application Block Policy is Empty")
                raise ConnectorError("Application Block Policy is Empty")
            return self.__get_request(url, payload)
        except Exception as Err:
            raise ConnectorError(Err)

    def __get_ip_network_group_details(self):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["SHOW_GROUP"])
            if self.ip_block_policy:
                payload = {'name': self.ip_block_policy}
            else:
                logger.exception("IP Address Block Policy is Empty")
                raise ConnectorError("IP Address Block Policy is Empty")
            return self.__get_request(url, payload=payload)
        except Exception as Err:
            raise ConnectorError(Err)

    def __get_app_url_all_details(self):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["APP_URL_DETAILS"])
            if self.url_block_policy:
                payload = {'name': self.url_block_policy}
            else:
                logger.exception("URL Block Policy is Empty")
                raise ConnectorError("URL Block Policy is Empty")
            return self.__get_request(url, payload=payload)
        except Exception as Err:
            raise ConnectorError(Err)

    def __set_sid(self):
        try:
            if self.session:
                url = '{0}{1}'.format(self.server_url, rest_api["KEEPALIVE_SESSION"])
                header = {'content-Type': 'application/json', 'X-chkp-sid': self.session["sid"]}
                payload = {}
                api_response = requests.post(url, data=json.dumps(payload), headers=header, verify=self.verify_ssl)
                if api_response.ok:
                    api_response = json.loads(api_response.content.decode('utf-8'))
                else:
                    logger.info('Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
                    raise ConnectorError(
                        'Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
            else:
                url = '{0}{1}'.format(self.server_url, rest_api["LOGIN_API"])
                payload = {'user': self.username, 'password': self.password}
                if self.domain:
                    payload.update({"domain":self.domain})
                header = {'content-Type': 'application/json'}
                api_response = requests.post(url, data=json.dumps(payload), headers=header, verify=self.verify_ssl)
                if api_response.ok:
                    try:
                        api_response = json.loads(api_response.content.decode('utf-8'))
                    except:
                        raise ConnectorError(api_response.content.decode('utf-8'))
                else:
                    logger.info('Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
                    raise ConnectorError(
                        'Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
            try:
                if api_response.get('message') == "OK":
                    self.session = self.session
                else:
                    self.session = api_response
            except Exception:
                self.sid = None
                logger.info('Sid Not Found. Invalid Username, Password or Domain')
                raise ConnectorError('Sid Not Found. Invalid Username, Password or Domain')
        except Exception as Err:
            raise ConnectorError(Err)

    def __get_request(self, url, payload={}, header=None):
        try:
            self.__set_sid()
            if not header:
                header = {'content-Type': 'application/json', 'X-chkp-sid': self.session["sid"]}
            api_response = requests.post(url, data=json.dumps(payload), headers=header, verify=self.verify_ssl)
            if api_response.ok:
                return json.loads(api_response.content.decode('utf-8'))
            else:
                logger.info('Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
                raise ConnectorError(
                    'Fail To request API {0} response is : {1}'.format(str(url), str(api_response.content)))
        except Exception as Err:
            raise ConnectorError(Err)

    def __get_all_hosts_details(self, offset=0):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["LIST_OF_NETWORK_HOST"])
            payload = {'offset': offset, 'limit': 500}
            api_response = self.__get_request(url, payload=payload)
            total = math.ceil(api_response.get("total") / 500)
            try:
                return api_response.get("objects"), total
            except Exception:
                logger.exception("Network Group Not Found {}".format(api_response))
                raise ConnectorError("Network Group Not Found {}".format(api_response))
        except Exception as Err:
            raise ConnectorError(Err)

    def __is_host_exist(self, ip_address_list):
        try:
            offset = 0
            old_hosts_list = []
            ip_address_list = [ipaddress.ip_address(ip).compressed for ip in ip_address_list]
            all_host, total = self.__get_all_hosts_details(offset)
            for x in range(0, total):
                if offset > 0:
                    all_host, _total = self.__get_all_hosts_details(offset)
                for host in all_host:
                    if host.get("ipv4-address"):
                        if host.get("ipv4-address") in ip_address_list:
                            old_hosts_list.append(host)
                            ip_address_list.remove(host["ipv4-address"])
                            self.status.update({str(host.get("ipv4-address")): "IP Address Host object Already There"})
                        continue
                    if host.get("ipv6-address"):
                        if host.get("ipv6-address") in ip_address_list:
                            old_hosts_list.append(host)
                            ip_address_list.remove(host["ipv6-address"])
                            self.status.update({str(host.get("ipv6-address")): "IP Address Host object Already There"})
                if len(ip_address_list) == 0:
                    break
                else:
                    offset += 500
            return old_hosts_list, ip_address_list
        except Exception as Err:
            raise ConnectorError(Err)

    def __create_host_object_with_group(self, new_hosts_list):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["ADD_HOST"])
            for ip_address in new_hosts_list:
                ip_type = ipaddress.ip_address(ip_address)
                if isinstance(ip_type, ipaddress.IPv6Address):
                    payload = {'name': 'cyops_' + str(ip_address), "ipv6-address": ip_address,
                               "groups": self.ip_block_policy}
                elif isinstance(ip_type, ipaddress.IPv4Address):
                    payload = {'name': 'cyops_' + str(ip_address), "ipv4-address": ip_address,
                               "groups": self.ip_block_policy}
                else:
                    logger.exception("IP Address is Not IPV4 or Not IPV6 : {}".format(ip_address))
                    self.status.update({str(ip_address): "IP Address is Not IPV4 or Not IPV6"})
                    continue
                api_response = self.__get_request(url, payload=payload)
                if api_response.get('uid'):
                    self.status.update({str(ip_address): "IP Address Block Successfully"})
                else:
                    self.status.update({str(ip_address): "IP Address NOT Block"})
            return self.status
        except Exception as Err:
            logger.exception("Not Able To Add Host Error is : {}".format(Err))
            raise ConnectorError("Not Able To Add Host Error is : {}".format(Err))

    def __add_existing_host_object_with_group(self, old_hosts_list):
        url = '{0}{1}'.format(self.server_url, rest_api["EDIT_HOST"])
        try:
            for ip_address in old_hosts_list:
                payload = {'uid': ip_address['uid'], 'groups': {"add": self.ip_block_policy}}
                api_response = self.__get_request(url, payload=payload)
                if api_response.get('uid'):
                    if ip_address.get("ipv4-address"):
                        self.status.update({str(ip_address["ipv4-address"]): "IP Address Block Successfully"})
                    else:
                        self.status.update({str(ip_address["ipv6-address"]): "IP Address Block Successfully"})
                else:
                    self.status.update({str(ip_address["ipv6-address"]): "IP Address NOT Block"})
            return self.status
        except Exception as Err:
            logger.exception("Not Able To Add Host Error is : {}".format(Err))
            raise ConnectorError("Not Able To Add Host Error is : {}".format(Err))

    def __delete_hosts(self, old_hosts_list):
        try:
            for host in old_hosts_list:
                url = '{0}{1}'.format(self.server_url, rest_api["DELETE_HOST"])
                payload = {"uid": host['uid'], "ignore-warnings": True, "ignore-errors": True}
                try:
                    api_response = self.__get_request(url, payload=payload)
                    if api_response.get('message'):
                        if host.get("ipv4-address"):
                            self.status.update({str(host["ipv4-address"]): "IP Address Unblock Successfully"})
                        else:
                            self.status.update({str(host["ipv6-address"]): "IP Address Unblock Successfully"})
                except Exception as Err:
                    logger.exception("Fail: {}".format(str(Err)))
                    if host.get("ipv4-address"):
                        self.status.update({str(host["ipv4-address"]): "IP Address Unblock Fail"})
                    else:
                        self.status.update({str(host["ipv6-address"]): "IP Address Unblock Fail"})
            return self.status
        except Exception as Err:
            raise ConnectorError(Err)

    def __publish(self):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["PUBLISH"])
            publish_response = self.__get_request(url)
            status = self.__check_show_task(publish_response["task-id"])
            return status, publish_response
        except Exception as Err:
            raise ConnectorError(Err)

    def __install_policy(self):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["INSTALL_POLICY"])
            payload = {"access": True, "policy-package": "Standard"}
            time_out = 300
            time_interval = 10
            while True:
                try:
                    install_response = self.__get_request(url, payload=payload)
                    status = self.__check_show_task(install_response["task-id"])
                    return status, install_response
                except Exception as Err:
                    if "A policy installation is currently in progress" in str(Err) and time_out > 0:
                        time.sleep(time_interval)
                        time_out = time_out - time_interval
                    else:
                        if time_out == 0:
                            return False, None
                        else:
                            raise ConnectorError(Err)
        except Exception as Err:
            raise ConnectorError(Err)

    def __get_list_from_str_or_list(self, params, parameter):
        try:
            parameter_list = params.get(parameter)
            if parameter_list:
                if isinstance(parameter_list, str):
                    parameter_list = parameter_list.split(",")
                    return parameter_list
                elif isinstance(parameter_list, list):
                    return parameter_list
            raise ConnectorError("{0} Are Not in Format or Empty: {1}".format(parameter, parameter_list))
        except Exception as Err:
            raise ConnectorError(Err)

    def logout(self):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["LOGOUT_SESSION"])
            return self.__get_request(url)
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def check_health(self):
        try:
            self.__set_sid()
            if self.session["sid"]:
                return True
            else:
                logger.info('Invalid Credentials or URL')
                raise ConnectorError('Invalid Credentials or URL')
        except Exception as Err:
            logger.exception("Check Health Fail {}".format(str(Err)))
            if 'certificate verify failed' in str(Err):
                logger.exception("Certificate Verify Failed {}".format(str(Err)))
                raise ConnectorError('Certificate Verify Failed')
            elif 'Failed to establish a new connection' in str(Err):
                logger.exception("Failed to establish a new connection Invalid URL or Credentials {}".format(str(Err)))
                raise ConnectorError('Failed to establish a new connection Invalid URL or Credentials')
            elif 'Authentication to server failed' in str(Err) or "Unauthorized" in str(Err):
                logger.exception("Authentication to server failed Invalid Username or Password {}".format(str(Err)))
                raise ConnectorError('Authentication to server failed Invalid Username or Password')
            elif 'This system is for authorized use only' in str(Err) or "Unauthorized" in str(Err):
                logger.exception("This system is for authorized use only {}".format(str(Err)))
                raise ConnectorError('This system is for authorized use only')
            else:
                raise ConnectorError(Err)

    def show_sessions(self, config, params):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["SHOW_SESSIONS"])
            payload = {'limit': 500}
            return self.__get_request(url, payload=payload)
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def get_session(self, config, params):
        try:
            session_id = get_input(params, "session_id", str)
            url = '{0}{1}'.format(self.server_url, rest_api["GET_SESSION"])
            payload = {'uid': session_id}
            return self.__get_request(url, payload=payload)
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def discard_session(self, config, params):
        try:
            url = '{0}{1}'.format(self.server_url, rest_api["DISCARD_SESSION"])
            if params.get("session_uid"):
                payload = {'uid': params.get("session_uid")}
                api_response = self.__get_request(url, payload=payload)
            else:
                api_response = self.__get_request(url)
            return api_response
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def block_ip(self, config, params):
        try:
            if not self.ip_block_policy:
                logger.exception("IP Address Block Policy is Empty")
                raise ConnectorError("IP Address Block Policy is Empty")
            ip_address_list = self.__get_list_from_str_or_list(params, "ip_address_list")
            old_hosts_list, new_hosts_list = self.__is_host_exist(ip_address_list)
            self.status = self.__create_host_object_with_group(new_hosts_list)
            self.status = self.__add_existing_host_object_with_group(old_hosts_list)
            return self.__publish_install_policy()
        except Exception as Err:
            discard_session_response = self.discard_session(config, params)
            logger.exception("Fail: {0}\n{1}".format(str(Err), str(discard_session_response)))
            raise ConnectorError(Err)

    def unblock_ip(self, config, params):
        try:
            ip_address_list = self.__get_list_from_str_or_list(params, "ip_address_list")
            old_hosts_list, new_hosts_list = self.__is_host_exist(ip_address_list)
            for ip_address in new_hosts_list:
                self.status.update({str(ip_address): "IP Address NOT Found In Block Stat"})
            self.status = self.__delete_hosts(old_hosts_list)
            return self.__publish_install_policy()
        except Exception as Err:
            discard_session_response = self.discard_session(config, params)
            logger.exception("Fail: {0}\n{1}".format(str(Err), str(discard_session_response)))
            raise ConnectorError(Err)

    def block_unblock_urls(self, config, params, is_block):
        try:
            url_list = self.__get_list_from_str_or_list(params, "url_list")
            url_block_policy_details = self.__get_app_url_all_details()
            if is_block:
                payload = {'uid': url_block_policy_details['uid'], 'url-list': {'add': url_list}}
            else:
                payload = {'uid': url_block_policy_details['uid'], 'url-list': {'remove': url_list}}
            url = '{0}{1}'.format(self.server_url, rest_api["EDIT_APP_URL"])
            response = self.__get_request(url, payload=payload)
            for url in url_list:
                if url in response["url-list"]:
                    if is_block:
                        self.status.update({str(url): "Successful"})
                    else:
                        self.status.update({str(url): "Failed"})
                else:
                    if is_block:
                        self.status.update({str(url): "Failed"})
                    else:
                        self.status.update({str(url): "Successful"})
            return self.__publish_install_policy()
        except Exception as Err:
            discard_session_response = self.discard_session(config, params)
            logger.exception("Fail: {0}\n{1}".format(str(Err), str(discard_session_response)))
            raise ConnectorError(Err)

    def block_unblock_application(self, config, params, is_block):
        try:
            app_list = self.__get_list_from_str_or_list(params, "app_list")
            app_group_details = self.__get_app_group_details()
            if is_block:
                payload = {'uid': app_group_details['uid'], 'members': {'add': app_list}, "ignore-warnings": True}
            else:
                payload = {'uid': app_group_details['uid'], 'members': {'remove': app_list}, "ignore-warnings": True}
            url = '{0}{1}'.format(self.server_url, rest_api["EDIT_APP_URL_GROUP"])
            response = self.__get_request(url, payload=payload)
            blocked_app_names = list(map(lambda app: app["name"], response["members"]))
            for app in app_list:
                if app in blocked_app_names:
                    if is_block:
                        self.status.update({str(app): "Application Block Successfully"})
                    else:
                        self.status.update({str(app): "Application Unblock Fail"})
                else:
                    if is_block:
                        self.status.update({str(app): "Application Block Fail"})
                    else:
                        self.status.update({str(app): "Application Unblock Successfully"})
            return self.__publish_install_policy()
        except Exception as Err:
            discard_session_response = self.discard_session(config, params)
            logger.exception("Fail: {0}\n{1}".format(str(Err), str(discard_session_response)))
            raise ConnectorError(Err)

    def get_blocked_application_names(self, config, params):
        try:
            app_group_details = self.__get_app_group_details()
            return list(map(lambda app: app['name'], app_group_details['members']))
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def get_blocked_urls(self, config, params):
        try:
            url_block_policy_details = self.__get_app_url_all_details()
            return url_block_policy_details['url-list']
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def get_blocked_ip_addresses(self, config, params):
        try:
            group_details = self.__get_ip_network_group_details()
            return list(map(lambda group: group['name'], group_details['members']))
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def get_list_of_applications(self, config, params):
        try:
            limit = get_input(params, "limit", int)
            start_index = get_input(params, "start_index", int)
            url = '{0}{1}'.format(self.server_url, rest_api["LIST_OF_APP"])
            payload = {'offset': start_index, 'limit': limit}
            return self.__get_request(url, payload=payload)
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def check_policies(self, config, params):
        try:
            app_policy_details = self.__get_app_group_details()
            if app_policy_details:
                self.status.update({"Application Block Policy": "Valid"})
            else:
                self.status.update({"Application Block Policy": "Invalid"})
            ip_policy_details = self.__get_ip_network_group_details()
            if ip_policy_details:
                self.status.update({"IP Address Block Policy": "Valid"})
            else:
                self.status.update({"IP Address Block Policy": "Invalid"})
            url_policy_details = self.__get_app_url_all_details()
            if url_policy_details:
                self.status.update({"URL Block Policy": "Valid"})
            else:
                self.status.update({"URL Block Policy": "Invalid"})
            return self.status
        except Exception as Err:
            logger.exception("Fail: {}".format(str(Err)))
            raise ConnectorError(Err)

    def block_urls(self, config, params):
        return self.block_unblock_urls(config, params, True)

    def unblock_urls(self, config, params):
        return self.block_unblock_urls(config, params, False)

    def block_applications(self, config, params):
        return self.block_unblock_application(config, params, True)

    def unblock_applications(self, config, params):
        return self.block_unblock_application(config, params, False)
