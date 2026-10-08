from flask import Flask, jsonify
from flask_cors import CORS
import pandas as pd
import os
from analyzer import analyze_logs

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({
        "message": "CyberDNA Backend is running!",
        "status": "success"
    })


@app.route("/api/logs")
def get_logs():
    file_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "dataset",
        "security_logs.csv"
    )

    try:
        data = pd.read_csv(file_path)

        return jsonify({
            "status": "success",
            "total_logs": len(data),
            "logs": data.to_dict(orient="records")
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)