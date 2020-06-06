import json

from psycopg2 import sql


class Items(object):

    class SingleItem(object):
        def __init__(self, db):
            self._db = db
            self.item_id = None
            self._primary_key = None
            self._table_name = None
            with open("Queries.json", "r+") as file:
                self._queries = json.load(file)
            file.close()

        def commit(self):
            cursor = self._db.get_cursor()
            action = "update"
            if self.item_id is None:
                action = "insert"
            params = self._params_builder(action)
            try:
                query = self._queries[self._table_name][action]
                cursor.execute(sql.SQL(query), params)
                self._db.commit()
                self.item_id = dict(cursor.fetchone())[self._primary_key]
            finally:
                cursor.close()

        def _params_builder(self, action):
            raise NotImplementedError()

    class ServerItem(SingleItem):
        def __init__(self, db, server_id=None, customer_id=None, server_ip=None, server_dns=None, active=None, time_stamp=None):
            super().__init__(db)
            self.item_id = server_id
            self.customer_id = customer_id
            self.server_ip = server_ip
            self.server_dns = server_dns
            self.active = active
            self.time_stamp = time_stamp
            self._table_name = "servers"
            self._primary_key = "server_id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.customer_id, self.server_ip, self.active, self.time_stamp]
            elif action == "update":
                params = [self.customer_id, self.server_ip, self.active, self.item_id]
            return params

    class CustomerItem(SingleItem):
        def __init__(self, db, customer_id=None, username=None, password=None, active=None, time_stamp=None):
            super().__init__(db)
            self.item_id = customer_id
            self.username = username
            self.password = password
            self.active = active
            self.time_stamp = time_stamp
            self._table_name = "customers"
            self._primary_key = "customer_id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.username, self.password, self.active, self.time_stamp]
            elif action == "update":
                params = [self.username, self.password, self.active, self.item_id]
            return params

    class BlackListItem(SingleItem):
        def __init__(self, db, item_id=None, ip=None, server_id=None, time_stamp=None):
            super().__init__(db)
            self.item_id = item_id
            self.ip = ip
            self.server_id = server_id
            self.time_stamp = time_stamp
            self._table_name = "blacklist"
            self._primary_key = "id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.ip, self.server_id, self.time_stamp]
            elif action == "update":
                params = [self.ip, self.server_id, self.item_id]
            return params

    class WhiteListItem(BlackListItem):
        def __init__(self, db, item_id=None, ip=None, server_id=None, time_stamp=None):
            super().__init__(db, item_id, ip, server_id, time_stamp)
            self._table_name = "whitelist"

    class HttpResponseItem(SingleItem):
        def __init__(self, db, response_id=None, request_id=None, method=None, content=None, from_server_id=None,
                     to_ip=None, decision=None, time_stamp=None):
            super().__init__(db)
            self.item_id = response_id
            self.request_id = request_id
            self.method = method
            self.content = content
            self.from_server_id = from_server_id
            self.to_ip = to_ip
            self.decision = decision
            self.time_stamp = time_stamp
            self._table_name = "http_responses"
            self._primary_key = "response_id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.request_id, self.method, self.content, self.from_server_id, self.to_ip, self.decision,
                          self.time_stamp]
            elif action == "update":
                params = [self.request_id, self.method, self.content, self.from_server_id, self.to_ip, self.decision,
                          self.item_id]
            return params

    class HttpRequestItem(SingleItem):
        def __init__(self, db, request_id=None, response_id=None, method=None, content=None, to_server_id=None,
                     from_ip=None, decision=None, time_stamp=None):
            super().__init__(db)
            self.item_id = request_id
            self.response_id = response_id
            self.method = method
            self.content = content
            self.from_ip = from_ip
            self.to_server_id = to_server_id
            self.decision = decision
            self.time_stamp = time_stamp
            self._table_name = "http_responses"
            self._primary_key = "request_id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.response_id, self.method, self.content, self.to_server_id, self.from_ip, self.decision,
                          self.time_stamp]
            elif action == "update":
                params = [self.response_id, self.method, self.content, self.to_server_id, self.from_ip, self.decision,
                          self.item_id]
            return params

    class DetectorRequestDataItem(SingleItem):
        def __init__(self, db, item_id=None, request_id=None, bruteforce=None, bots=None, cookie_poisoning=None, csrf=None,
                     ddos=None, sql_injection=None, xml_injection=None, xss_injection=None):
            super().__init__(db)
            self.item_id = item_id
            self.request_id = request_id
            self.bruteforce = bruteforce
            self.bots = bots
            self.cookie_poisoning = cookie_poisoning
            self.csrf = csrf
            self.ddos = ddos
            self.sql_injection = sql_injection
            self.xml_injection = xml_injection
            self.xss_injection = xss_injection
            self._table_name = "detectors_requests_data"
            self._primary_key = "id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.request_id, self.bruteforce, self.bots, self.cookie_poisoning, self.csrf, self.ddos,
                          self.sql_injection, self.xml_injection, self.xss_injection]
            elif action == "update":
                params = [self.request_id, self.bruteforce, self.bots, self.cookie_poisoning, self.csrf, self.ddos,
                          self.sql_injection, self.xml_injection, self.xss_injection, self.item_id]
            return params

    class MLRequestData(DetectorRequestDataItem):
        def __init__(self, db, item_id=None, request_id=None, bruteforce=None, bots=None, cookie_poisoning=None, csrf=None,
                     ddos=None, sql_injection=None, xml_injection=None, xss_injection=None):
            super().__init__(db, item_id, request_id, bruteforce, bots, cookie_poisoning, csrf, ddos, sql_injection,
                             xml_injection, xss_injection)
            self._table_name = "ml_requests_data"

    class DetectorDataResponseItem(SingleItem):
        def __init__(self, db, item_id=None, response_id=None, user_protection=None, xss_injection=None):
            super().__init__(db)
            self.item_id = item_id
            self.response_id = response_id
            self.user_protection = user_protection
            self.xss_injection = xss_injection
            self._table_name = "detectors_data_responses"
            self._primary_key = "id"

        def _params_builder(self, action):
            params = []
            if action == "insert":
                params = [self.response_id, self.user_protection, self.xss_injection]
            elif action == "update":
                params = [self.response_id, self.user_protection, self.xss_injection, self.item_id]
            return params

    class MLDataResponseItem(DetectorDataResponseItem):
        def __init__(self, db, item_id=None, response_id=None, user_protection=None, xss_injection=None):
            super().__init__(db, item_id, response_id, user_protection, xss_injection)
            self._table_name = "ml_data_responses"
