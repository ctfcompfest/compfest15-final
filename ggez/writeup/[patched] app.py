from flask import Flask, render_template, request
import pandas as pd
import json
import string

app = Flask(__name__)
db = pd.read_csv("heroes_data.csv")

@app.route('/')
def index():
    heroes = json.loads(db.to_json(orient='records'))

    context = {
            'status' : "get",
            'heroes' : heroes
        }
    return render_template('index.html' ,context=context)

@app.route("/search", methods=['POST'])
def search():
    if request.method == "POST" and request.form['keyword']:
        keyword = request.form['keyword']

        for char in keyword:
            if char in string.ascii_letters or char in string.digits:
                continue
            else:
                keyword.replace(char, "")


        pattern = f".*{keyword}.*"
        res = db.query(f"localized_name.str.contains(@pattern, case=False)", local_dict={'pattern': pattern})
        
        data = json.loads(res.to_json(orient='records'))

        if len(data) > 0 :
            status = "found"
        else:
            status = "not_found"

        context = {
            'status' : status,
            'heroes' : data,
            'query' : keyword
        }
        return render_template('index.html', context = context)
    return render_template('index.html', context = None)    


@app.route('/detail')
def detail():
    name = request.args.get('name')

    for char in name:
            if char in string.ascii_letters or char in string.digits:
                continue
            else:
                name.replace(char, "")
                
    query = db.query(f"`localized_name` == '{name}'").to_json(orient='records')
    heroes = json.loads(query) 
    heroes[0]['roles'] = heroes[0]['roles'][1:-1].replace("'","").split(",")
    print(heroes[0]['roles'])
    return render_template('hero.html' ,hero=heroes[0])

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True, port=8000)
