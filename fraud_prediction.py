from creditcard.logger import logging
from creditcard.exception import CreditCardsException
from creditcard.pipeline.batch_prediction import CreditCardBatchPrediction
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
import json
import pandas as pd


#class MyFlaskApp:
    #def __init__(self,app,prediction_results):
        #self.app = Flask(__name__)
        #self.prediction_results = {}
        #self.define_routes()
        

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'  # Secret key for JWT
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600 # Access token expiration time (in seconds)

jwt = JWTManager(app)

prediction_results = {}

users = {
    'user1': {'password': 'password1', 'role': 'user'},
    'user2': {'password': 'password2', 'role': 'admin'}
}

# Endpoint for user authentication and token generation
@app.route('/login', methods=['POST'])
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'message': 'Authentication required!'}), 401

    username = auth.username
    password = auth.password

    if username in users and users[username]['password'] == password:
        access_token = create_access_token(identity=username)
        return jsonify({'access_token': access_token}), 200

    return jsonify({'message': 'Invalid credentials'}), 401

#def define_routes(self):
@app.route('/predict', methods=['POST'])
@jwt_required()
def predict():
            try:
                # Receive transaction Data As JSON 
                transaction_data = request.get_json()
                #data = json.loads(transaction_data)
                df = pd.DataFrame(transaction_data, index=[0])

                # Perform fraud prediction (replace with your actual prediction logic)
                # For this example, we'll just return a random prediction (0 for legitimate, 1 for fraudulent)
                #prediction=0 if df.amount.values[0]<100 else 1
                credit_card_batch_prediction = CreditCardBatchPrediction(data=df)
                prediction = credit_card_batch_prediction.start_prediction()


                # Store the prediction result
                prediction_results[transaction_data.get('id')] = prediction

                # Return the prediction result
                return jsonify({"prediction": prediction})
        
            except Exception as e:
                return jsonify({"error":str(e)}), 500
            
# Endpoint for retrieving prediction results
@app.route('/get_prediction/<id>', methods=['GET'])
@jwt_required()
def get_prediction(id):
            try:
                # Retrieve the prediction result for a specific transaction
                prediction = prediction_results.get(id, -1)  # -1 Indicates No Prediction Available

                return jsonify({"prediction": prediction})

            except Exception as e:
                return jsonify({"error": str(e)}), 500
    #def run(self):
        #self.app.run(debug=True)

#app_1 = MyFlaskApp()

if __name__ == '__main__':
    #app_1 = MyFlaskApp()
    app.run(debug=True)