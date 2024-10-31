from flask import Flask, request
from flask_restful import Api, Resource
import osquery

class User(Resource):
    @staticmethod
    def get():
        instance = osquery.SpawnInstance()
        instance.open()
        query = request.args.get('query', default='', type=str)
        query = instance.client.query(query)
        return query.response, 200
        
    @staticmethod
    def post():
        instance = osquery.SpawnInstance()
        instance.open()
        query = request.data
        query = instance.client.query(query)
        return query.response, 200


app = Flask(__name__)
api = Api(app)
api.add_resource(User, "/exec")
app.run(host='0.0.0.0', debug=True, threaded=True, port=8082)
