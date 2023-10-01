from flask import Flask, request

app = Flask(__name__)

@app.route('/', methods=['POST'])
def process_data():
    data = request.form['flag']

    # Handle submit the flag to the flag server here
    print(data)
    return f'{data}'

if __name__ == '__main__':
    app.run(debug=True, port=5001)

