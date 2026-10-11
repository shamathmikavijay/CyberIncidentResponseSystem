CyberShield web frontend

Copy app.py, templates/ and static/ into your existing CyberIncidentResponseSystem project folder.
Keep the existing database/ folder unchanged.

From VS Code terminal:
python -m pip install -r requirements.txt
python app.py

Enter the MySQL password when prompted (input hidden), then open:
http://127.0.0.1:5000

The MySQL database name defaults to cyber_incident_db. Set MYSQL_DATABASE if yours differs.
Do not publish your MySQL password to GitHub.

Dashboard: 5 recent incidents
Incidents: 10 per page with search/filter and CRUD
Reports: summary counts

Deletion is intentionally blocked for incidents with response actions, reports, or audit history to preserve seeded data. Create a test incident, edit it, then delete it for the demonstration.
