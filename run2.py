from flask import Flask, request, render_template, redirect, url_for
import subprocess
import os
import json
import mysql.connector
from mysql.connector import Error
import json
import google.generativeai as genai  

app = Flask(__name__)

QUERY_FILE = 'queries.json'
IP_FILE = 'ips.json'

genai.configure(api_key="your API key of google gemini")

model = genai.GenerativeModel('gemini-1.5-pro-latest')
chat = model.start_chat(history=[])

def create_connection():
    try:
        connection = mysql.connector.connect(
            host='localhost',
            database='osquery_db',
            user='root',  
            password='',
            port='3307' 
        )
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
    return None

def load_queries():
    if os.path.exists(QUERY_FILE):
        with open(QUERY_FILE, 'r') as file:
            return json.load(file)
    return []

def save_queries(queries):
    with open(QUERY_FILE, 'w') as file:
        json.dump(queries, file)

def load_ips():
    if os.path.exists(IP_FILE):
        with open(IP_FILE, 'r') as file:
            return json.load(file)
    return []

def save_ips_to_db():
    ips = load_ips()
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        for ip in ips:
            cursor.execute("INSERT IGNORE INTO saved_ips (ip) VALUES (%s)", (ip,))
        connection.commit()
        cursor.close()
        connection.close()

def save_scan(ip, port, query, process_name, output):
    connection = create_connection()
    if connection:
        cursor = connection.cursor()
        cursor.execute("INSERT INTO hosts (ip, port) VALUES (%s, %s)", (ip, port))
        host_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO scansions (host_id, query, process_name, output) VALUES (%s, %s, %s, %s)",
            (host_id, query, process_name, output)
        )
        connection.commit()
        cursor.close()
        connection.close()

def get_scansions(filter_ip=None):
    connection = create_connection()
    scansions = []
    if connection:
        cursor = connection.cursor(dictionary=True)
        query = """
            SELECT scansions.id, hosts.ip, hosts.port, scansions.query, scansions.process_name, scansions.output, scansions.scan_time 
            FROM scansions 
            JOIN hosts ON scansions.host_id = hosts.id 
            {}
            ORDER BY scansions.scan_time DESC
        """
        if filter_ip:
            query = query.format("WHERE hosts.ip = %s")
            cursor.execute(query, (filter_ip,))
        else:
            query = query.format("")
            cursor.execute(query)
        scansions = cursor.fetchall()
        cursor.close()
        connection.close()
    return scansions

def explain_output_with_ai(output):
    
    prompt = f"Explain the output of this scansion, be professional and don't be too verbose:\n\n{output}"
    
    response = chat.send_message(prompt)
    
    return response.text

@app.route('/', methods=['GET', 'POST'])
def index():
    filter_ip = request.args.get('filter_ip')
    if request.method == 'POST':
        if 'execute' in request.form:
            ip = request.form.get('ip')
            port = request.form.get('port')
            process_name = request.form.get('process_name')
            query = request.form.get('query')
            if not (ip and port and query):
                return "Missing parameters", 400

            ips = load_ips()
            if ip not in ips:
                ips.append(ip)
                save_ips_to_db()

            query_encoded = query.replace(" ", "%20")
            command = f'curl -H "Content-Type: application/json" -X GET http://{ip}:{port}/exec?query={query_encoded}'
            if process_name:
                command += f' | grep {process_name}'

            try:
                result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
                output = result.stdout
            except subprocess.CalledProcessError as e:
                output = str(e)

            save_scan(ip, port, query, process_name, output)

            explain_response = explain_output_with_ai(output)

            queries = load_queries()
            scansions = get_scansions(filter_ip=filter_ip)
            ips = load_ips()
            return render_template('index.html', queries=queries, output=output, ips=ips, last_ip=ip, scansions=scansions, explain_output=explain_response)

        elif 'save_query' in request.form:
            query_name = request.form.get('query_name')
            query_text = request.form.get('query_text')

            if not (query_name and query_text):
                return "Missing parameters", 400
            queries = load_queries()
            queries.append({"name": query_name, "query": query_text})
            save_queries(queries)
            return redirect(url_for('index'))

    queries = load_queries()
    scansions = get_scansions(filter_ip=filter_ip)
    ips = load_ips()
    save_ips_to_db()  
    return render_template('index.html', queries=queries, ips=ips, scansions=scansions)

@app.route('/delete_query/<query_name>', methods=['POST'])
def delete_query(query_name):
    queries = load_queries()
    queries = [q for q in queries if q['name'] != query_name]
    save_queries(queries)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
