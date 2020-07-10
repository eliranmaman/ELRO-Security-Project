from flask import Flask
from flask_restful import Resource, Api

app = Flask(__name__)
api = Api(app)


class LoginHandler(Resource):
    def post(self):
        return {'hello': 'world'}


class RegisterHandler(Resource):
    def post(self):
        return {'bla': 'world'}


class GetActiveServicesHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class GetUsersDataHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class GetCustomersStatisticsHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class UpdateServiceStatusHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class AdminUpdateServiceStatusHandler(Resource):
    def post(self):
        return {'bye': 'world'}


class AddNewWebsiteHandler(Resource):
    def post(self):
        return {'bye': 'world'}


api.add_resource(LoginHandler, '/login')
api.add_resource(RegisterHandler, '/register')
api.add_resource(GetActiveServicesHandler, '/getActiveServices')
api.add_resource(GetUsersDataHandler, '/getUsersData')
api.add_resource(GetCustomersStatisticsHandler, '/getCustomersStatistics')
api.add_resource(UpdateServiceStatusHandler, '/updateServiceStatus')
api.add_resource(AdminUpdateServiceStatusHandler, '/adminUpdateServiceStatus')
api.add_resource(AddNewWebsiteHandler, '/addNewWebsite')

if __name__ == '__main__':
    app.run(debug=True)