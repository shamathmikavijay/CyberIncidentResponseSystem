import math
import tkinter as tk
from tkinter import ttk, messagebox
from backend.database import get_connection

BG = '#0b1422'
SIDE = '#0e1929'
PANEL = '#152237'
FIELD = '#1d2e46'
BORDER = '#273951'
FG = '#edf3fa'
MUTED = '#9bacc2'
BLUE = '#42a9ed'
GREEN = '#46b99b'
RED = '#ed6974'
YELLOW = '#edbd61'
SEVERITIES = ('Low', 'Medium', 'High', 'Critical')
STATUSES = ('Open', 'Investigating', 'Contained', 'Resolved', 'Closed')
TYPES = ('Malware', 'Phishing', 'Data Breach', 'DDoS')
PAGE_SIZE = 10


class IncidentDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title('CyberShield | Incident Response Management')
        self.root.geometry('1420x850')
        self.root.minsize(1060, 660)
        self.root.configure(bg=BG)
        self.page = 1
        self.view = 'Dashboard'
        self.search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value='All statuses')
        self.employees = {}
        self.categories = {}
        self.total_matches = 0
        self.selected_id = None
        self.configure_style()
        self.build()
        self.load_lookups()
        self.refresh()

    def configure_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Cyber.Treeview', background=PANEL, foreground=FG,
                        fieldbackground=PANEL, rowheight=42, borderwidth=0,
                        font=('Segoe UI', 10))
        style.configure('Cyber.Treeview.Heading', background=FIELD, foreground=MUTED,
                        font=('Segoe UI', 10, 'bold'), relief='flat', padding=9)
        style.map('Cyber.Treeview', background=[('selected', '#264c70')],
                  foreground=[('selected', '#ffffff')])
        style.configure('Cyber.TCombobox', fieldbackground=FIELD, background=FIELD,
                        foreground='#142338', padding=6)
        style.configure('Cyber.Vertical.TScrollbar', background=FIELD, troughcolor=PANEL)

    def text(self, parent, value, size=10, color=FG, bold=False, **kwargs):
        return tk.Label(parent, text=value, bg=parent.cget('bg'), fg=color,
                        font=('Segoe UI', size, 'bold' if bold else 'normal'), **kwargs)

    def button(self, parent, label, command, primary=False, danger=False):
        color = BLUE if primary else ('#9e4051' if danger else FIELD)
        foreground = '#081625' if primary else FG
        return tk.Button(parent, text=label, command=command, bg=color, fg=foreground,
                         activebackground='#348dc6' if primary else BORDER,
                         activeforeground=FG, relief='flat', bd=0, padx=16, pady=10,
                         font=('Segoe UI', 10, 'bold'), cursor='hand2')

    def build(self):
        sidebar = tk.Frame(self.root, bg=SIDE, width=215)
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)
        brand = tk.Frame(sidebar, bg=SIDE, padx=24, pady=30)
        brand.pack(fill='x')
        self.text(brand, 'CYBERSHIELD', 17, BLUE, True).pack(anchor='w')
        self.text(brand, 'Incident Response', 10, MUTED).pack(anchor='w', pady=(3, 0))
        self.nav = {}
        for label in ('Dashboard', 'Incidents', 'Reports'):
            btn = tk.Button(sidebar, text='   ' + label, anchor='w', bg=SIDE,
                            fg=MUTED, activebackground=PANEL, activeforeground=FG,
                            relief='flat', bd=0, padx=22, pady=15,
                            font=('Segoe UI', 11), cursor='hand2',
                            command=lambda name=label: self.switch(name))
            btn.pack(fill='x', pady=2)
            self.nav[label] = btn
        self.text(sidebar, 'CONNECTED TO MYSQL', 9, MUTED).pack(side='bottom', pady=24)

        self.main = tk.Frame(self.root, bg=BG)
        self.main.pack(side='left', fill='both', expand=True)
        header = tk.Frame(self.main, bg=BG, padx=28, pady=22)
        header.pack(fill='x')
        headleft = tk.Frame(header, bg=BG)
        headleft.pack(side='left')
        self.heading = self.text(headleft, 'Dashboard', 22, FG, True)
        self.heading.pack(anchor='w')
        self.subtitle = self.text(headleft, 'Overview of security incidents', 10, MUTED)
        self.subtitle.pack(anchor='w', pady=(3, 0))
        self.button(header, 'Refresh', self.refresh).pack(side='right')

        self.body = tk.Frame(self.main, bg=BG, padx=28, pady=4)
        self.body.pack(fill='both', expand=True)
        self.stats = tk.Frame(self.body, bg=BG)
        self.stats.pack(fill='x', pady=(0, 22))
        self.stat_labels = {}
        cards = [('Total Incidents', BLUE), ('Active Incidents', GREEN),
                 ('Critical Incidents', RED), ('Resolved / Closed', GREEN)]
        for index, (title, accent) in enumerate(cards):
            card = tk.Frame(self.stats, bg=PANEL, highlightbackground=BORDER,
                            highlightthickness=1, padx=19, pady=17)
            card.grid(row=0, column=index, sticky='ew', padx=(0 if index == 0 else 6, 6))
            self.stats.columnconfigure(index, weight=1)
            self.text(card, title, 10, MUTED).pack(anchor='w')
            value = self.text(card, '—', 25, accent, True)
            value.pack(anchor='w', pady=(6, 0))
            self.stat_labels[title] = value

        toolbar = tk.Frame(self.body, bg=BG)
        toolbar.pack(fill='x', pady=(0, 12))
        self.section_title = self.text(toolbar, 'Recent Incidents', 15, FG, True)
        self.section_title.pack(side='left')
        self.add_btn = self.button(toolbar, '+ Add Incident', self.add, primary=True)
        self.add_btn.pack(side='right')
        self.edit_btn = self.button(toolbar, 'Edit', self.edit)
        self.edit_btn.pack(side='right', padx=(0, 8))
        self.delete_btn = self.button(toolbar, 'Delete', self.delete, danger=True)
        self.delete_btn.pack(side='right', padx=(0, 8))

        self.table_panel = tk.Frame(self.body, bg=PANEL, highlightbackground=BORDER,
                                    highlightthickness=1, padx=15, pady=15)
        self.table_panel.pack(fill='both', expand=True)
        filters = tk.Frame(self.table_panel, bg=PANEL)
        filters.pack(fill='x', pady=(0, 12))
        self.search = tk.Entry(filters, textvariable=self.search_var, bg=FIELD, fg=FG,
                               insertbackground=FG, relief='flat', font=('Segoe UI', 10))
        self.search.pack(side='left', fill='x', expand=True, ipady=9)
        self.search.bind('<Return>', lambda event: self.new_search())
        self.status_combo = ttk.Combobox(filters, textvariable=self.filter_var,
                                          values=('All statuses',) + STATUSES,
                                          state='readonly', width=18, style='Cyber.TCombobox')
        self.status_combo.pack(side='left', padx=9)
        self.status_combo.bind('<<ComboboxSelected>>', lambda event: self.new_search())
        self.button(filters, 'Search', self.new_search).pack(side='left')
        self.button(filters, 'Clear', self.clear_search).pack(side='left', padx=(7, 0))

        table_frame = tk.Frame(self.table_panel, bg=PANEL)
        table_frame.pack(fill='both', expand=True)
        cols = ('ID', 'Title', 'Type', 'Severity', 'Status', 'Reported by', 'Date')
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings',
                                 selectmode='browse', style='Cyber.Treeview')
        widths = {'ID': 50, 'Title': 285, 'Type': 115, 'Severity': 90,
                  'Status': 120, 'Reported by': 145, 'Date': 155}
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=widths[col], minwidth=widths[col], anchor='w')
        self.tree.grid(row=0, column=0, sticky='nsew')
        scroll_y = ttk.Scrollbar(table_frame, orient='vertical', command=self.tree.yview)
        scroll_y.grid(row=0, column=1, sticky='ns')
        self.tree.configure(yscrollcommand=scroll_y.set)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.tree.bind('<Double-1>', lambda event: self.edit())
        self.tree.tag_configure('Critical', foreground='#ff9aa0')
        self.tree.tag_configure('High', foreground='#f3b37e')

        footer = tk.Frame(self.table_panel, bg=PANEL)
        footer.pack(fill='x', pady=(13, 0))
        self.count_label = self.text(footer, '', 10, MUTED)
        self.count_label.pack(side='left')
        self.next_btn = self.button(footer, 'Next  >', self.next_page)
        self.next_btn.pack(side='right')
        self.page_label = self.text(footer, 'Page 1', 10, MUTED)
        self.page_label.pack(side='right', padx=16)
        self.prev_btn = self.button(footer, '<  Previous', self.prev_page)
        self.prev_btn.pack(side='right')

        self.reports_panel = tk.Frame(self.body, bg=PANEL, highlightbackground=BORDER,
                                      highlightthickness=1, padx=24, pady=24)
        self.report_label = self.text(self.reports_panel, '', 12, FG, justify='left')
        self.report_label.pack(anchor='nw')
        self.switch('Dashboard')

    def switch(self, view):
        self.view = view
        for name, btn in self.nav.items():
            btn.configure(bg=PANEL if name == view else SIDE,
                          fg=BLUE if name == view else MUTED)
        self.heading.configure(text=view)
        self.subtitle.configure(text={'Dashboard': 'Overview of security incidents',
                                     'Incidents': 'Search and manage incident records',
                                     'Reports': 'Incident summary from the database'}[view])
        if view == 'Reports':
            self.stats.pack_forget()
            self.table_panel.pack_forget()
            self.section_title.master.pack_forget()
            self.reports_panel.pack(fill='both', expand=True)
        else:
            self.reports_panel.pack_forget()
            self.stats.pack(fill='x', pady=(0, 22), before=self.section_title.master)
            self.section_title.master.pack(fill='x', pady=(0, 12), before=self.table_panel)
            self.table_panel.pack(fill='both', expand=True)
            self.section_title.configure(text='Recent Incidents' if view == 'Dashboard' else 'Incident Registry')
        if hasattr(self, 'tree'):
            self.page = 1
            self.refresh()

    def load_lookups(self):
        try:
            con = get_connection()
            try:
                cur = con.cursor()
                cur.execute('SELECT EmployeeID, Name FROM Employee ORDER BY Name')
                self.employees = {f'{name} (#{eid})': eid for eid, name in cur.fetchall()}
                cur.execute('SELECT CategoryID, CategoryName FROM ThreatCategory ORDER BY CategoryName')
                self.categories = {f'{name} (#{cid})': cid for cid, name in cur.fetchall()}
                cur.close()
            finally:
                con.close()
        except Exception as exc:
            messagebox.showerror('Database error', str(exc))

    def refresh(self):
        try:
            con = get_connection()
            try:
                cur = con.cursor()
                cur.execute('''SELECT COUNT(*),
                    COALESCE(SUM(Status IN ('Open','Investigating','Contained')),0),
                    COALESCE(SUM(SeverityLevel='Critical'),0),
                    COALESCE(SUM(Status IN ('Resolved','Closed')),0) FROM Incident''')
                counts = cur.fetchone()
                for widget, value in zip(self.stat_labels.values(), counts):
                    widget.configure(text=str(value or 0))
                self.report_label.configure(text=(
                    f'Total incidents: {counts[0]}\n\n'
                    f'Active incidents: {counts[1]}\n\n'
                    f'Critical incidents: {counts[2]}\n\n'
                    f'Resolved or closed: {counts[3]}\n\n'
                    'Use the Incidents page to search, add, edit, or delete records.'))
                pattern = '%' + self.search_var.get().strip() + '%'
                status = self.filter_var.get()
                where = '''FROM Incident i JOIN Employee e ON e.EmployeeID=i.ReportedByID
                    WHERE (i.Title LIKE %s OR CAST(i.IncidentID AS CHAR) LIKE %s)
                    AND (%s='All statuses' OR i.Status=%s)'''
                params = (pattern, pattern, status, status)
                cur.execute('SELECT COUNT(*) ' + where, params)
                self.total_matches = cur.fetchone()[0]
                max_page = max(1, math.ceil(self.total_matches / PAGE_SIZE))
                self.page = min(self.page, max_page)
                cur.execute('''SELECT i.IncidentID, i.Title, i.IncidentType,
                    i.SeverityLevel, i.Status, e.Name,
                    DATE_FORMAT(i.DateReported, '%Y-%m-%d %H:%i') ''' + where +
                    ' ORDER BY i.IncidentID DESC LIMIT %s OFFSET %s',
                    params + (PAGE_SIZE, (self.page - 1) * PAGE_SIZE))
                rows = cur.fetchall()
                cur.close()
            finally:
                con.close()
            self.tree.delete(*self.tree.get_children())
            for row in rows:
                self.tree.insert('', 'end', values=row, tags=(row[3],))
            self.selected_id = None
            self.count_label.configure(text=f'Showing {len(rows)} of {self.total_matches} matching incidents')
            self.page_label.configure(text=f'Page {self.page} of {max_page}')
            self.prev_btn.configure(state='normal' if self.page > 1 else 'disabled')
            self.next_btn.configure(state='normal' if self.page < max_page else 'disabled')
        except Exception as exc:
            messagebox.showerror('Database error', str(exc))

    def new_search(self):
        self.page = 1
        self.refresh()

    def clear_search(self):
        self.search_var.set('')
        self.filter_var.set('All statuses')
        self.new_search()

    def prev_page(self):
        if self.page > 1:
            self.page -= 1
            self.refresh()

    def next_page(self):
        if self.page * PAGE_SIZE < self.total_matches:
            self.page += 1
            self.refresh()

    def on_select(self, event=None):
        selected = self.tree.selection()
        self.selected_id = int(self.tree.item(selected[0], 'values')[0]) if selected else None

    def get_record(self, incident_id):
        con = get_connection()
        try:
            cur = con.cursor()
            cur.execute('''SELECT Title, Description, IncidentType, SeverityLevel,
                Status, ReportedByID, CategoryID FROM Incident WHERE IncidentID=%s''',
                (incident_id,))
            record = cur.fetchone()
            cur.close()
            return record
        finally:
            con.close()

    def add(self):
        self.form()

    def edit(self):
        if self.selected_id is None:
            messagebox.showwarning('Select incident', 'Select an incident to edit.')
            return
        try:
            record = self.get_record(self.selected_id)
            if record is None:
                self.refresh()
                messagebox.showwarning('Not found', 'This incident no longer exists.')
                return
            self.form(self.selected_id, record)
        except Exception as exc:
            messagebox.showerror('Database error', str(exc))

    def form(self, incident_id=None, record=None):
        win = tk.Toplevel(self.root)
        win.title('Add Incident' if incident_id is None else f'Edit Incident #{incident_id}')
        win.geometry('670x600')
        win.minsize(600, 560)
        win.configure(bg=BG)
        win.transient(self.root)
        win.grab_set()
        wrapper = tk.Frame(win, bg=BG, padx=28, pady=24)
        wrapper.pack(fill='both', expand=True)
        self.text(wrapper, 'Add Incident' if incident_id is None else f'Edit Incident #{incident_id}',
                  19, FG, True).pack(anchor='w', pady=(0, 18))
        vars_ = {'title': tk.StringVar(value=record[0] if record else ''),
                 'type': tk.StringVar(value=record[2] if record else 'Malware'),
                 'severity': tk.StringVar(value=record[3] if record else 'Medium'),
                 'status': tk.StringVar(value=record[4] if record else 'Open'),
                 'employee': tk.StringVar(), 'category': tk.StringVar()}
        if record:
            vars_['employee'].set(next((n for n, eid in self.employees.items() if eid == record[5]), ''))
            vars_['category'].set(next((n for n, cid in self.categories.items() if cid == record[6]), ''))
        fields = tk.Frame(wrapper, bg=BG)
        fields.pack(fill='both', expand=True)
        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(1, weight=1)

        def field(label, key, row, col, options=None):
            cell = tk.Frame(fields, bg=BG)
            cell.grid(row=row, column=col, sticky='ew', padx=(0, 12) if col == 0 else (12, 0), pady=8)
            self.text(cell, label, 10, MUTED).pack(anchor='w', pady=(0, 6))
            if options is None:
                widget = tk.Entry(cell, textvariable=vars_[key], bg=FIELD, fg=FG,
                                  insertbackground=FG, relief='flat', font=('Segoe UI', 11))
                widget.pack(fill='x', ipady=9)
            else:
                widget = ttk.Combobox(cell, textvariable=vars_[key], values=list(options),
                                      state='readonly', style='Cyber.TCombobox')
                widget.pack(fill='x')
            return widget

        field('Incident title *', 'title', 0, 0)
        field('Reported by *', 'employee', 0, 1, self.employees)
        type_combo = field('Incident type *', 'type', 1, 0, TYPES)
        if record:
            type_combo.configure(state='disabled')
        field('Threat category *', 'category', 1, 1, self.categories)
        field('Severity *', 'severity', 2, 0, SEVERITIES)
        field('Status *', 'status', 2, 1, STATUSES)
        self.text(fields, 'Description', 10, MUTED).grid(row=3, column=0, columnspan=2,
                                                       sticky='w', pady=(12, 6))
        description = tk.Text(fields, height=6, bg=FIELD, fg=FG, insertbackground=FG,
                              relief='flat', wrap='word', font=('Segoe UI', 11), padx=9, pady=8)
        description.grid(row=4, column=0, columnspan=2, sticky='nsew')
        description.insert('1.0', record[1] or '' if record else '')
        fields.rowconfigure(4, weight=1)
        controls = tk.Frame(wrapper, bg=BG)
        controls.pack(fill='x', pady=(18, 0))
        self.button(controls, 'Cancel', win.destroy).pack(side='right', padx=(8, 0))

        def save():
            title = vars_['title'].get().strip()
            employee = self.employees.get(vars_['employee'].get())
            category = self.categories.get(vars_['category'].get())
            if not title or employee is None or category is None:
                messagebox.showwarning('Missing fields', 'Enter a title, reporting employee and threat category.', parent=win)
                return
            data = (title, description.get('1.0', 'end').strip(), vars_['status'].get(),
                    vars_['severity'].get(), vars_['type'].get(), employee, category)
            con = None
            try:
                con = get_connection()
                con.start_transaction()
                cur = con.cursor()
                if incident_id is None:
                    cur.execute('''INSERT INTO Incident
                        (Title, Description, Status, SeverityLevel, IncidentType, ReportedByID, CategoryID)
                        VALUES (%s,%s,%s,%s,%s,%s,%s)''', data)
                    new_id = cur.lastrowid
                    kind = data[4]
                    if kind == 'Malware':
                        cur.execute('INSERT INTO MalwareIncident (IncidentID, MalwareType, InfectedFiles) VALUES (%s,%s,0)', (new_id, 'Unclassified'))
                    elif kind == 'Phishing':
                        cur.execute('INSERT INTO PhishingIncident (IncidentID, TargetEmails) VALUES (%s,0)', (new_id,))
                    elif kind == 'Data Breach':
                        cur.execute('INSERT INTO DataBreachIncident (IncidentID, RecordsCompromised) VALUES (%s,0)', (new_id,))
                    else:
                        cur.execute('INSERT INTO DDoSIncident (IncidentID, PeakTrafficVolume, SourceIPCount) VALUES (%s,0,0)', (new_id,))
                    saved_id = new_id
                else:
                    cur.execute('SELECT IncidentType FROM Incident WHERE IncidentID=%s FOR UPDATE', (incident_id,))
                    original = cur.fetchone()
                    if original is None or original[0] != data[4]:
                        raise ValueError('Incident missing or incident type was changed.')
                    cur.execute('''UPDATE Incident SET Title=%s, Description=%s, Status=%s,
                        SeverityLevel=%s, IncidentType=%s, ReportedByID=%s, CategoryID=%s
                        WHERE IncidentID=%s''', data + (incident_id,))
                    saved_id = incident_id
                con.commit()
                win.destroy()
                self.page = 1
                self.clear_search()
                messagebox.showinfo('Saved', f'Incident #{saved_id} saved successfully.')
            except Exception as exc:
                if con:
                    con.rollback()
                messagebox.showerror('Save failed', str(exc), parent=win)
            finally:
                if con:
                    con.close()

        self.button(controls, 'Save Incident', save, primary=True).pack(side='right')
        win.bind('<Escape>', lambda event: win.destroy())

    def delete(self):
        if self.selected_id is None:
            messagebox.showwarning('Select incident', 'Select an incident to delete.')
            return
        incident_id = self.selected_id
        if not messagebox.askyesno('Confirm deletion',
                f'Permanently delete incident #{incident_id} and its related actions, reports and audit history?\n\nFor testing, delete only your own new incident.'):
            return
        con = None
        try:
            con = get_connection()
            con.start_transaction()
            cur = con.cursor()
            cur.execute('DELETE FROM IncidentAudit WHERE IncidentID=%s', (incident_id,))
            cur.execute('DELETE FROM ResponseAction WHERE IncidentID=%s', (incident_id,))
            cur.execute('DELETE FROM IncidentReport WHERE IncidentID=%s', (incident_id,))
            cur.execute('DELETE FROM Incident WHERE IncidentID=%s', (incident_id,))
            if cur.rowcount != 1:
                raise ValueError('Incident not found.')
            con.commit()
            self.refresh()
            messagebox.showinfo('Deleted', f'Incident #{incident_id} deleted.')
        except Exception as exc:
            if con:
                con.rollback()
            messagebox.showerror('Delete failed', str(exc))
        finally:
            if con:
                con.close()
