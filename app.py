import os
import getpass
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import mysql.connector
from mysql.connector import Error

app = Flask(__name__)
DB_PASSWORD = os.getenv('MYSQL_PASSWORD')

def connect():
    return mysql.connector.connect(host=os.getenv('MYSQL_HOST', 'localhost'), user=os.getenv('MYSQL_USER', 'root'), password=DB_PASSWORD, database=os.getenv('MYSQL_DATABASE', 'cyber_incident_db'))

def rows(sql, args=()):
    con = connect()
    try:
        cur = con.cursor(dictionary=True)
        cur.execute(sql, args)
        result = cur.fetchall()
        for item in result:
            for k, v in item.items():
                if isinstance(v, datetime): item[k] = v.strftime('%Y-%m-%d %H:%M')
        return result
    finally:
        con.close()

def stats():
    return rows("""SELECT COUNT(*) total, COALESCE(SUM(Status IN ('Open','Investigating','Contained')),0) active, COALESCE(SUM(SeverityLevel='Critical'),0) critical, COALESCE(SUM(Status IN ('Resolved','Closed')),0) resolved FROM Incident""")[0]

BASE = """SELECT i.IncidentID id, i.Title title, i.Description description, i.IncidentType type, i.SeverityLevel severity, i.Status status, i.ReportedByID employee_id, i.CategoryID category_id, e.Name reporter, c.CategoryName category, DATE_FORMAT(i.DateReported, '%Y-%m-%d %H:%i') reported FROM Incident i JOIN Employee e ON i.ReportedByID=e.EmployeeID JOIN ThreatCategory c ON i.CategoryID=c.CategoryID"""

@app.route('/')
def dashboard():
    recent = rows(BASE + ' ORDER BY i.IncidentID DESC LIMIT 5')
    return render_template('index.html', page='dashboard', stats=stats(), incidents=recent)

@app.route('/incidents')
def incidents():
    return render_template('index.html', page='incidents', stats=stats(), incidents=[])

@app.route('/reports')
def reports():
    severity = rows('SELECT SeverityLevel label, COUNT(*) count FROM Incident GROUP BY SeverityLevel ORDER BY FIELD(SeverityLevel,\'Critical\',\'High\',\'Medium\',\'Low\')')
    status = rows('SELECT Status label, COUNT(*) count FROM Incident GROUP BY Status')
    types = rows('SELECT IncidentType label, COUNT(*) count FROM Incident GROUP BY IncidentType')
    return render_template('index.html', page='reports', stats=stats(), incidents=[], severity=severity, status=status, types=types)

@app.route('/api/lookups')
def lookups():
    return jsonify(employees=rows('SELECT EmployeeID id, Name name FROM Employee ORDER BY Name'), categories=rows('SELECT CategoryID id, CategoryName name FROM ThreatCategory ORDER BY CategoryName'))

@app.route('/api/incidents')
def incident_list():
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    term = request.args.get('search', '').strip()
    status = request.args.get('status', '').strip()
    conditions = ['(i.Title LIKE %s OR CAST(i.IncidentID AS CHAR) LIKE %s)']
    params = ['%' + term + '%', '%' + term + '%']
    if status and status != 'All statuses':
        conditions.append('i.Status = %s')
        params.append(status)
    where = ' WHERE ' + ' AND '.join(conditions)
    total = rows('SELECT COUNT(*) total FROM Incident i' + where, tuple(params))[0]['total']
    total_pages = max(1, (total + 9) // 10)
    page = min(page, total_pages)
    data = rows(BASE + where + ' ORDER BY i.IncidentID DESC LIMIT 10 OFFSET %s', tuple(params + [(page - 1) * 10]))
    return jsonify(incidents=data, total=total, page=page, pages=total_pages)

@app.route('/api/incidents/<int:incident_id>')
def incident_detail(incident_id):
    found = rows(BASE + ' WHERE i.IncidentID=%s', (incident_id,))
    return (jsonify(found[0]), 200) if found else (jsonify(error='Incident not found'), 404)

def validate(data):
    title = str(data.get('title', '')).strip()
    if not title or len(title) > 200:
        raise ValueError('Title is required (maximum 200 characters).')
    kind = data.get('type')
    severity = data.get('severity')
    status = data.get('status')
    if kind not in ('Malware', 'Phishing', 'Data Breach', 'DDoS') or severity not in ('Low', 'Medium', 'High', 'Critical') or status not in ('Open', 'Investigating', 'Contained', 'Resolved', 'Closed'):
        raise ValueError('Select valid type, severity and status.')
    try:
        employee = int(data.get('employee_id'))
        category = int(data.get('category_id'))
    except (ValueError, TypeError):
        raise ValueError('Select an employee and threat category.')
    return title, str(data.get('description', '')).strip(), status, severity, kind, employee, category

@app.route('/api/incidents', methods=['POST'])
def add_incident():
    con = None
    try:
        values = validate(request.get_json(silent=True) or {})
        con = connect()
        cur = con.cursor()
        cur.execute('INSERT INTO Incident (Title, Description, Status, SeverityLevel, IncidentType, ReportedByID, CategoryID) VALUES (%s,%s,%s,%s,%s,%s,%s)', values)
        new_id = cur.lastrowid
        kind = values[4]
        if kind == 'Malware':
            cur.execute('INSERT INTO MalwareIncident (IncidentID, MalwareType, InfectedFiles) VALUES (%s,%s,0)', (new_id, 'Unclassified'))
        elif kind == 'Phishing':
            cur.execute('INSERT INTO PhishingIncident (IncidentID, TargetEmails) VALUES (%s,0)', (new_id,))
        elif kind == 'Data Breach':
            cur.execute('INSERT INTO DataBreachIncident (IncidentID, RecordsCompromised) VALUES (%s,0)', (new_id,))
        else:
            cur.execute('INSERT INTO DDoSIncident (IncidentID, PeakTrafficVolume, SourceIPCount) VALUES (%s,0,0)', (new_id,))
        con.commit()
        return jsonify(message=f'Incident #{new_id} created', id=new_id), 201
    except (ValueError, Error) as exc:
        if con: con.rollback()
        return jsonify(error=str(exc)), 400
    finally:
        if con: con.close()

@app.route('/api/incidents/<int:incident_id>', methods=['PUT'])
def edit_incident(incident_id):
    con = None
    try:
        values = validate(request.get_json(silent=True) or {})
        con = connect()
        cur = con.cursor()
        cur.execute('SELECT IncidentType FROM Incident WHERE IncidentID=%s FOR UPDATE', (incident_id,))
        existing = cur.fetchone()
        if not existing: raise ValueError('Incident not found.')
        if existing[0] != values[4]: raise ValueError('Incident type cannot be changed after creation.')
        cur.execute('UPDATE Incident SET Title=%s, Description=%s, Status=%s, SeverityLevel=%s, IncidentType=%s, ReportedByID=%s, CategoryID=%s WHERE IncidentID=%s', values + (incident_id,))
        con.commit()
        return jsonify(message=f'Incident #{incident_id} updated')
    except (ValueError, Error) as exc:
        if con: con.rollback()
        return jsonify(error=str(exc)), 400
    finally:
        if con: con.close()

@app.route('/api/incidents/<int:incident_id>', methods=['DELETE'])
def delete_incident(incident_id):
    con = None
    try:
        con = connect()
        cur = con.cursor()
        cur.execute('SELECT IncidentID FROM Incident WHERE IncidentID=%s FOR UPDATE', (incident_id,))
        if not cur.fetchone(): raise ValueError('Incident not found.')
        # Prevent accidental destruction of seeded incident histories and response records.
        for table in ('ResponseAction', 'IncidentReport', 'IncidentAudit'):
            cur.execute(f'SELECT COUNT(*) FROM {table} WHERE IncidentID=%s', (incident_id,))
            if cur.fetchone()[0]:
                raise ValueError('This incident has related actions, reports or audit history. For the CRUD demo, delete a newly added test incident instead.')
        cur.execute('DELETE FROM Incident WHERE IncidentID=%s', (incident_id,))
        con.commit()
        return jsonify(message=f'Incident #{incident_id} deleted')
    except (ValueError, Error) as exc:
        if con: con.rollback()
        return jsonify(error=str(exc)), 400
    finally:
        if con: con.close()

if __name__ == '__main__':
    if DB_PASSWORD is None:
        DB_PASSWORD = getpass.getpass('MySQL password (input hidden): ')
    app.run(debug=False, port=5000)
