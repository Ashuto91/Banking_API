from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.BankAPI
users = db["Users"]

def UserExist(username):
    if users.find({"Username": username}).count == 0:
        return False
    else:
        return True

# This class will contain Registration Details /
class Register(Resource):

    #step 1 is to get input from the user
    postedData = request.get_json()

    #get the data
    username = postedData["username"]
    password = postedData["password"]

    if UserExist(username):
        retJson = {
            'status': 301,
            'msg': 'Invalid Username'
        }
        return jsonify(retjson)

    hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

    # Lets store username and password into database
    users.insert({
        "Username": username,
        "Password": hashed_pw,
        "Own": 0,
        "Debt": 0
    })


def verifwPw(username, password):
    if not UserExist(username,password):
        return False

    hashed_pw = users.find({
        "username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def cashWithUser(username):
    cash = users.find({
        "Username":username
    })[0]["Own"]
    return cash


def debtWithUser(username):
    debt = users.find({
        "Username": username
    })[0]["Debt"]
    return debt


def generateReturnDictionary(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson


def verifyCredentials(username, password):
    if not UserExist(username):
        return generateReturnDictionary(301, "Invalid Username"), True

    correct_pw = verifwPw(username,password)

    if not correct_pw:
        return generateReturnDictionary(302, "Invalid Password"), True

    return None, False

def updateAccount(username, balance):
    users.update({
        "Username": username
    }, {
        "$set":{
            "Own": balance
        }
    })

def updateDebt(username, balance):
    users.update(
        {
            "Username": username
        },
        {
            "$set": {
                "Debt": balance
            }
        }
    )


class Add(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["Username"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        if money <= 0:
            return jsonify(generateReturnDictionary(304, "The money amount entered must be greater than 0"))

        cash = cashWithUser(username)
        money -= 1

        bank_cash = cashWithUser("Bank")
        updateAccount("Bank", bank_cash + 1)
        updateAccount(username,cash + money)

        return jsonify(generateReturnDictionary(200, "Amount added successfully"))


class Transfer(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["Username"]
        password = postedData["Password"]
        to       = postedData["to"]
        money    = postedData["amount"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        if cash <= 0:
            return jsonify(generateReturnDictionary(303, Out of money))

        if money <= 0:
            return jsonify(generateReturnDictionary(304, "The money amount enetered must be greater than 0"))

        if not UserExist(to):
            return jsonify(generateReturnDictionary(301, Received username incorrect))

        cash_from = cashWithUser(username)
        cash_to   = cashWithUser(to)
        bank_cash = cashWithUser("BANK")

        updateAccount("BANK", bank_cash + 1)
        updateAccount(to, cash_to + money - 1)
        updateAccount(username, cash_from - money)

        retJson = {
            "status": 200,
            "msg": "Amount added successfully to account"
        }
        return jsonify(generateReturnDictionary(200, "Amount added successfully"))


class Balance(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData("username")
        password = postedData("password")

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        retJson = users.find({
            "Username": username
        },{
            "Password": 0,
            "_id": 0
        })[0]
        return jsonify(retJson)


class Takeloan(Resource):
    def post(self):
        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money    = postedData["amount"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        debt = debtWithUser(username)
        updateAccount(username, cash + money)
        updateDebt(username, debt + money)

        return jsonify(generateReturnDictionary(200, "Loan added to your account"))


class PayLoan(Resource):
    postedData = request.get_json()

    username = postedData["username"]
    password = postedData["password"]
    money    = postedData["amount"]

    retJson, error = verifyCredentials(username, password)
    if error:
        return jsonify(retJson)

    cash = cashWithUser(username)

    if cash < money:
        return jsonify(generateReturnDictionary(303, "Not enough cash in your account"))

    debt = debtWithUser(username)
    updateAccount(username, cash - money)
    updateDebt(username, debt - money)

    return jsonify(generateReturnDictionary(200, "Loan Paid"))


api.add_resource(Register, '/register')
api.add_resource(add, '/add')
api.add_resource(Transfer, '/transfer')
api.add_resource(Balance, '/balance')
api.add_resource(Takeloan, '/takeloan')
api.add_resource(PayLoan, '/payloan')


if __name__=="__main__":
    app.run(host='0.0.0.0')

