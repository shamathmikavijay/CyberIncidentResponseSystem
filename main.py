import tkinter as tk
from frontend.dashboard import IncidentDashboard

if __name__ == '__main__':
    root = tk.Tk()
    IncidentDashboard(root)
    root.mainloop()
