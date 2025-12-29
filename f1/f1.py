import sys
import threading
import os
import fastf1
import pandas as pd

# PyQt6 Imports (The GUI Library)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTextEdit, 
                             QVBoxLayout, QHBoxLayout, QWidget, 
                             QPushButton, QLabel, QGridLayout, QComboBox)
from PyQt6.QtGui import QTextCursor
from PyQt6.QtCore import QObject, pyqtSignal, Qt,QCoreApplication

# =====================================================
# 1. HELPER CLASSES
# =====================================================

class Stream(QObject):
    """
    Redirects Python 'print' statements to the GUI text box.
    """
    new_text = pyqtSignal(str)
    def write(self, text): self.new_text.emit(str(text))
    def flush(self): 
        # This forces the GUI to update the screen immediately.
        # Useful if your text is "lagging" behind long calculations.
        QCoreApplication.processEvents()


# =====================================================
# 2. BACKEND LOGIC (FastF1 Engine)
# =====================================================

class F1TelemetryHub:
    def __init__(self, cache_dir="f1_cache"):
        # Create a cache folder to store downloaded race data
        self.cache_dir = cache_dir
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
            
        # Optimize pandas settings
        pd.options.mode.chained_assignment = None 
        
        # Enable FastF1 Cache (Critical for speed)
        fastf1.Cache.enable_cache(self.cache_dir)
        
        self.current_session = None
        self.session_type = None  # e.g., 'R', 'FP1'
        self.sub_session = None   # e.g., 'Q1', 'Q2', 'Q3'

    #  Helpers 
    def _format_time(self, timedelta_obj):
        """Converts a raw timedelta into a clean string like '1:31.050'."""
        if pd.isna(timedelta_obj): return "-"
        total_seconds = timedelta_obj.total_seconds()
        minutes = int(total_seconds // 60)
        seconds = total_seconds % 60
        return f"{minutes}:{seconds:06.3f}"

    def _get_tyre_color(self, compound):
        """Returns the Hex Color code for a specific tyre compound."""
        if compound == "SOFT": return "#FF3333"      # Red
        if compound == "MEDIUM": return "#FFFF33"    # Yellow
        if compound == "HARD": return "#FFFFFF"      # White
        if compound == "INTERMEDIATE": return "#33FF33" # Green
        if compound == "WET": return "#3333FF"       # Blue
        return "#CCC" # Grey for unknown

    # Core Functions
    def load_session(self, year, grand_prix, session_type):
        """Downloads the race data."""
        # Logic: If user picks Q1/Q2/Q3, we download the main 'Q' session
        if session_type in ['Q1', 'Q2', 'Q3']:
            self.session_type = 'Q'
            self.sub_session = session_type
        else:
            self.session_type = session_type
            self.sub_session = None

        display_name = self.sub_session if self.sub_session else self.session_type
        
        print(f"<span style='color:#00AAFF'><b>[*] Downloading:</b> {year} {grand_prix} ({display_name})...</span>")
        print("<i>(This may take a moment...)</i>")
        
        try:
            session = fastf1.get_session(int(year), grand_prix, self.session_type)
            session.load()
            self.current_session = session
            print(f"<span style='color:#00FF41'><b>[$] Session Loaded!</b></span> {session.event['EventName']}")
            
            if self.sub_session:
                print(f"<span style='color:orange'>[i] Mode Active: Filtering data for <b>{self.sub_session}</b> only.</span>")
        
        except Exception as e:
            print(f"<span style='color:red'>[!] Error: {e}</span>")

    def get_results(self):
        """Decides which table to show based on the session type."""
        if not self.current_session: return
        
        mode = self.sub_session if self.sub_session else "SESSION"
        print(f"<h3 style='color:#00AAFF'>🏁 {mode} CLASSIFICATION</h3>")
        
        # If viewing Q1/Q2/Q3 specific times
        if self.sub_session:
            self._print_qualifying_segment_table()
        
        # If viewing Practice (FP1/FP2/FP3)
        elif self.session_type in ['FP1', 'FP2', 'FP3']:
            self._print_practice_table()
        
        # Standard Race Table
        else:
            self._print_race_table()

    #  Table Generators 
    def _print_qualifying_segment_table(self):
        """Generates table specifically for Q1, Q2, or Q3 results."""
        col_name = self.sub_session
        driver_data = []
        results = self.current_session.results
        
        for index, row in results.iterrows():
            driver_code = row['Abbreviation']
            q_time = row[col_name]
            
            # Defaults
            time_str = "-"
            sort_val = pd.Timedelta.max
            comp_str = "-"
            comp_color = "#CCC"
            
            if not pd.isna(q_time):
                time_str = self._format_time(q_time)
                sort_val = q_time
                
                # Try to find which tyre was used for this time
                try:
                    d_laps = self.current_session.laps.pick_drivers(driver_code)
                    # Find lap matching exact time
                    lap = d_laps[d_laps['LapTime'] == q_time]
                    if not lap.empty:
                        comp_str = lap.iloc[0]['Compound']
                        comp_color = self._get_tyre_color(comp_str)
                    else:
                        # Fallback to fastest lap
                        fastest = d_laps.pick_fastest()
                        if fastest is not None:
                            comp_str = fastest['Compound']
                            comp_color = self._get_tyre_color(comp_str)
                except:
                    pass

                driver_data.append({
                    "code": driver_code, "team": row['TeamName'], 
                    "time": time_str, "sort": sort_val,
                    "comp": comp_str, "color": comp_color
                })

        # Sort by fastest time
        driver_data.sort(key=lambda x: x['sort'])

        if not driver_data:
            print(f"<span style='color:orange'>[!] No times recorded for {self.sub_session}.</span>")
            return

        # Build HTML Table
        html_table = f"""<table border='1' cellpadding='8' cellspacing='0' width='100%' style='border-color:#444; font-size:14px; border-collapse: collapse;'>
                   <tr style='background-color:#222; color:#AAA;'>
                       <th align='center'>Pos</th>
                       <th align='left'>Driver</th>
                       <th align='left'>Team</th>
                       <th align='center'>Compound</th>
                       <th align='center'>{self.sub_session} Time</th>
                   </tr>"""
        
        for i, d in enumerate(driver_data):
            pos = i + 1
            pos_style = "color:#00FF41; font-weight:bold; font-size:16px;" if pos == 1 else "color:white;"
            
            html_table += f"""<tr>
                <td align='center' style='{pos_style}'>{pos}</td>
                <td><b>{d['code']}</b></td>
                <td style='color:#CCC'>{d['team']}</td>
                <td align='center' style='color:{d['color']}; font-weight:bold;'>{d['comp']}</td>
                <td align='center' style='color:#00FF41'><b>{d['time']}</b></td>
            </tr>"""
        
        print(html_table + "</table><br>")

    def _print_practice_table(self):
        """Generates table for Practice sessions (sorted by speed)."""
        driver_data = []
        results = self.current_session.results
        
        for index, row in results.iterrows():
            driver_code = row['Abbreviation']
            d_laps = self.current_session.laps.pick_drivers(driver_code)
            
            comp_str, laps_count, time_str, comp_color = "-", 0, "-", "#CCC"
            sort_val = pd.Timedelta.max

            if not d_laps.empty:
                laps_count = len(d_laps)
                best_lap = d_laps.pick_fastest()
                
                if best_lap is not None and not pd.isna(best_lap['LapTime']):
                    comp_str = best_lap['Compound']
                    comp_color = self._get_tyre_color(comp_str)
                    time_str = self._format_time(best_lap['LapTime'])
                    sort_val = best_lap['LapTime']
                else:
                    time_str = "No Time"

            driver_data.append({
                "code": driver_code, "team": row['TeamName'], "comp": comp_str,
                "color": comp_color, "laps": laps_count, "time": time_str, "sort": sort_val
            })

        driver_data.sort(key=lambda x: x['sort'])

        html_table = """<table border='1' cellpadding='8' cellspacing='0' width='100%' style='border-color:#444; font-size:14px; border-collapse: collapse;'>
                   <tr style='background-color:#222; color:#AAA;'>
                       <th align='left'>Driver</th>
                       <th align='left'>Team</th>
                       <th align='center'>Compound</th>
                       <th align='center'>Laps</th>
                       <th align='center'>Fastest Time</th>
                   </tr>"""
        
        for d in driver_data:
            html_table += f"""<tr>
                <td><b>{d['code']}</b></td>
                <td style='color:#CCC'>{d['team']}</td>
                <td align='center' style='color:{d['color']}; font-weight:bold;'>{d['comp']}</td>
                <td align='center'>{d['laps']}</td>
                <td align='center' style='color:#00FF41'><b>{d['time']}</b></td>
            </tr>"""
        
        print(html_table + "</table><br>")

    def _print_race_table(self):
        """Generates standard Race table."""
        results = self.current_session.results
        html_table = """<table border='1' cellpadding='8' cellspacing='0' width='100%' style='border-color:#444; font-size:14px; border-collapse: collapse;'>
                   <tr style='background-color:#222; color:#AAA;'>
                       <th align='center'>Pos</th>
                       <th align='left'>Driver</th>
                       <th align='left'>Team</th>
                       <th align='center'>Grid</th>
                       <th align='left'>Status</th>
                   </tr>"""
        
        for index, row in results.iterrows():
            pos = str(int(row['Position'])) if not pd.isna(row['Position']) else "NC"
            pos_style = "color:#00FF41; font-weight:bold; font-size:16px;" if pos == "1" else "color:white;"
            
            grid = "-"
            if 'GridPosition' in row and not pd.isna(row['GridPosition']):
                grid = str(int(row['GridPosition']))
                if grid == "0": grid = "<span style='color:orange'>Pit</span>"

            html_table += f"""<tr>
                <td align='center' style='{pos_style}'>{pos}</td>
                <td><b>{row['Abbreviation']}</b></td>
                <td style='color:#CCC'>{row['TeamName']}</td>
                <td align='center'>{grid}</td>
                <td>{row['Status']}</td>
            </tr>"""
        print(html_table + "</table><br>")

    #  Analysis Functions 
    def analyze_driver(self, driver_code):
        """Shows detailed stats for a single driver."""
        if not self.current_session: return
        print(f"<h2 style='color:#00AAFF'>📊 ANALYSIS: {driver_code}</h2>")
        
        try:
            laps = self.current_session.laps.pick_drivers(driver_code)
            if len(laps) == 0:
                print(f"<span style='color:orange'>[!] No laps recorded for {driver_code}.</span>")
                return

            # Determine Target Lap (Q1/Q2/Q3 vs Overall Fastest)
            target_lap = None
            if self.sub_session:
                try:
                    official_time = self.current_session.results.loc[
                        self.current_session.results['Abbreviation'] == driver_code, 
                        self.sub_session
                    ].values[0]
                    if not pd.isna(official_time):
                        target_lap = laps[laps['LapTime'] == official_time].iloc[0]
                    else:
                        print(f"<span style='color:orange'>[!] Driver did not set a valid time in {self.sub_session}.</span>")
                        return
                except:
                    target_lap = laps.pick_fastest()
            else:
                target_lap = laps.pick_fastest()

            # Compound Performance Table
            compounds = laps['Compound'].dropna().unique()
            print("<h3 style='color:#DDD; margin-bottom:5px;'>🛞 Tyre Compound Performance</h3>")
            
            compound_table = """<table border='1' cellpadding='8' cellspacing='0' width='100%' style='font-size:14px; border-collapse: collapse; border-color:#444;'>
                     <tr style='background-color:#222; color:#AAA;'>
                        <th align='left'>Compound</th>
                        <th align='center'>Laps Run</th>
                        <th align='center'>Best Time</th>
                        <th align='center'>Avg Pace</th>
                     </tr>"""

            for comp in compounds:
                comp_laps = laps[laps['Compound'] == comp]
                clean_laps = comp_laps.pick_quicklaps().dropna(subset=['LapTime'])
                lap_count = len(comp_laps)
                
                if clean_laps.empty:
                    best_str, avg_str = "-", "-"
                else:
                    best_str = self._format_time(clean_laps.pick_fastest()['LapTime'])
                    avg_str = self._format_time(clean_laps['LapTime'].mean())
                
                c_color = self._get_tyre_color(comp)
                compound_table += f"""<tr>
                    <td style='color:{c_color}; font-weight:bold;'>{comp}</td>
                    <td align='center'>{lap_count}</td>
                    <td align='center' style='color:#00FF41'><b>{best_str}</b></td>
                    <td align='center'>{avg_str}</td>
                </tr>"""
            print(compound_table + "</table><br>")

            # Fastest Lap Card
            if target_lap is not None:
                tel = target_lap.get_telemetry()
                ft_str = self._format_time(target_lap['LapTime'])
                top_speed = tel['Speed'].max() if not tel.empty else 0
                tyre_col = self._get_tyre_color(target_lap['Compound'])
                
                lbl = f"🚀 Best Lap ({self.sub_session})" if self.sub_session else "🚀 Absolute Fastest Lap"

                print(f"<h3 style='color:#DDD; margin-bottom:5px;'>{lbl}</h3>")
                print(f"""
                <div style='background-color:#222; padding:10px; border:1px solid #444;'>
                    <span style='font-size:16px;'>Time: <b style='color:#00FF41'>{ft_str}</b></span><br>
                    <span style='color:#CCC'>Tyre: <b style='color:{tyre_col}'>{target_lap['Compound']}</b> ({int(target_lap['TyreLife'])} laps old)</span><br>
                    <span style='color:#CCC'>Top Speed: {top_speed:.1f} km/h</span>
                </div><br>
                """)
        except Exception as e:
            print(f"<span style='color:red'>[!] Error: {e}</span>")

    def compare_drivers(self, d1, d2):
        """Compares two drivers head-to-head."""
        if not self.current_session: return
        print(f"<h2 style='color:#00AAFF'>⚔️ HEAD TO HEAD: {d1} vs {d2}</h2>")
        try:
            laps_d1 = self.current_session.laps.pick_drivers(d1)
            laps_d2 = self.current_session.laps.pick_drivers(d2)
            l1, l2 = None, None

            # Find matching laps based on mode (Q1/Q2/Q3 vs Overall)
            if self.sub_session:
                try:
                    time_d1 = self.current_session.results.loc[self.current_session.results['Abbreviation'] == d1, self.sub_session].values[0]
                    time_d2 = self.current_session.results.loc[self.current_session.results['Abbreviation'] == d2, self.sub_session].values[0]
                    if not pd.isna(time_d1): l1 = laps_d1[laps_d1['LapTime'] == time_d1].iloc[0]
                    if not pd.isna(time_d2): l2 = laps_d2[laps_d2['LapTime'] == time_d2].iloc[0]
                except: pass
            else:
                l1 = laps_d1.pick_fastest()
                l2 = laps_d2.pick_fastest()
            
            if l1 is None or l2 is None: 
                print(f"<span style='color:orange'>[!] Comparison unavailable. Missing data for {self.sub_session}.</span>")
                return

            # Compare Times
            delta = (l1['LapTime'] - l2['LapTime']).total_seconds()
            winner, loser, gap = (d1, d2, abs(delta)) if delta < 0 else (d2, d1, abs(delta))
            
            t1_str = self._format_time(l1['LapTime'])
            t2_str = self._format_time(l2['LapTime'])
            col1 = self._get_tyre_color(l1['Compound'])
            col2 = self._get_tyre_color(l2['Compound'])

            print(f"""
            <div style='font-size:15px; margin-bottom:10px;'>
                Winner: <b style='color:#00FF41'>{winner}</b> (-{gap:.3f}s)<br>
                <span style='color:#AAA'>
                    {d1}: {t1_str} <span style='color:{col1}'>({l1['Compound']})</span><br>
                    {d2}: {t2_str} <span style='color:{col2}'>({l2['Compound']})</span>
                </span>
            </div>
            """)
            
            # Sector Table
            sector_table = """<table border='1' cellpadding='8' cellspacing='0' width='100%' style='font-size:14px; border-collapse: collapse; border-color:#444;'>
                     <tr style='background-color:#222; color:#AAA;'>
                        <th>Sector</th>
                        <th>""" + d1 + """</th>
                        <th>""" + d2 + """</th>
                     </tr>"""
            
            for i in [1, 2, 3]:
                sec_name = f"Sector{i}Time"
                t1_s = l1[sec_name].total_seconds()
                t2_s = l2[sec_name].total_seconds()
                c1 = "#00FF41" if t1_s < t2_s else "#BBB"
                c2 = "#00FF41" if t2_s < t1_s else "#BBB"
                w1 = "font-weight:bold;" if t1_s < t2_s else ""
                w2 = "font-weight:bold;" if t2_s < t1_s else ""
                sector_table += f"""<tr>
                    <td align='center' style='color:#FFF'>S{i}</td>
                    <td align='center' style='color:{c1}; {w1}'>{t1_s:.3f}</td>
                    <td align='center' style='color:{c2}; {w2}'>{t2_s:.3f}</td>
                </tr>"""
            print(sector_table + "</table><br>")
        except Exception as e:
            print(f"<span style='color:red'>[!] Error: {e}</span>")


# =====================================================
# 3. FRONTEND UI (PyQt Window)
# =====================================================

class F1AnalyzerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.engine = F1TelemetryHub()
        
        # Setup Text Output Box
        self.output_log = QTextEdit()
        self.output_log.setReadOnly(True)
        self.output_log.setStyleSheet("""
            background-color: #1e1e1e; 
            color: #E0E0E0; 
            font-family: 'Segoe UI', sans-serif; 
            font-size: 14px; 
            padding: 15px;
            border: 1px solid #333;
        """)
        
        # Connect 'print' to the Text Box
        sys.stdout = Stream(new_text=self.on_print)
        sys.stderr = Stream(new_text=self.on_print)
        self.initUI()

    def on_print(self, text):
        if text.strip():
            self.output_log.insertHtml(text + "<br>")
            self.output_log.moveCursor(QTextCursor.MoveOperation.End)

    def initUI(self):
        self.setWindowTitle('F1 Telemetry Analyzer Pro')
        self.setGeometry(100, 100, 1100, 750)
        self.setStyleSheet("background-color: #2D2D2D; color: white;")

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Main Header
        header = QLabel("FORMULA 1 TELEMETRY HUB")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #FF1801; margin: 10px; letter-spacing: 1px;")
        layout.addWidget(header)

        # Settings Row (Dropdowns)
        settings_layout = QHBoxLayout()
        settings_layout.setSpacing(10)
        
        # Year
        self.combo_year = QComboBox()
        self.combo_year.addItems(["2025", "2024", "2023", "2022", "2021", "2020"])
        self.combo_year.setCurrentText("2024")
        
        # Grand Prix
        self.combo_gp = QComboBox()
        gps = ["Bahrain", "Saudi Arabia", "Australia", "Japan", "China", "Miami", "Emilia Romagna", 
               "Monaco", "Canada", "Spain", "Austria", "Great Britain", "Hungary", "Belgium", 
               "Netherlands", "Italy", "Azerbaijan", "Singapore", "United States", "Mexico", 
               "Brazil", "Las Vegas", "Qatar", "Abu Dhabi"]
        self.combo_gp.addItems(gps)
        
        # Session Type 
        self.combo_session = QComboBox()
        self.combo_session.addItems(["Q1", "Q2", "Q3", "R", "FP1", "FP2", "FP3", "Sprint"])
        
        # Load Button
        self.btn_load = QPushButton("LOAD SESSION")
        self.btn_load.clicked.connect(self.run_load)
        self.style_btn(self.btn_load, color="#FF1801")

        settings_layout.addWidget(QLabel("Year:"))
        settings_layout.addWidget(self.combo_year)
        settings_layout.addWidget(QLabel("GP:"))
        settings_layout.addWidget(self.combo_gp)
        settings_layout.addWidget(QLabel("Session:"))
        settings_layout.addWidget(self.combo_session)
        settings_layout.addWidget(self.btn_load)
        layout.addLayout(settings_layout)

        # Add Log Box to Layout
        layout.addWidget(self.output_log)

        # Analysis Row (Drivers & Actions)
        analysis_layout = QGridLayout()
        analysis_layout.setVerticalSpacing(10)
        analysis_layout.setHorizontalSpacing(10)
        
        drivers = ["VER", "PER", "LEC", "HAM", "RUS", "SAI", "NOR", "PIA", "ALO", "STR", 
                   "GAS", "OCO", "ALB", "SAR", "TSU", "RIC", "BOT", "ZHO", "HUL", "MAG", "BEA", "COL"]
        drivers.sort()

        self.combo_d1 = QComboBox()
        self.combo_d1.addItems(drivers)
        self.combo_d1.setCurrentText("VER")

        self.combo_d2 = QComboBox()
        self.combo_d2.addItems(drivers)
        self.combo_d2.setCurrentText("LEC")

        # Action Buttons
        self.btn_results = QPushButton("Show Leaderboard")
        self.btn_results.clicked.connect(self.run_results)
        self.style_btn(self.btn_results)
        
        self.btn_telemetry_d1 = QPushButton("Analyze Driver 1")
        self.btn_telemetry_d1.clicked.connect(self.run_telemetry_d1)
        self.style_btn(self.btn_telemetry_d1)

        self.btn_telemetry_d2 = QPushButton("Analyze Driver 2")
        self.btn_telemetry_d2.clicked.connect(self.run_telemetry_d2)
        self.style_btn(self.btn_telemetry_d2)
        
        self.btn_compare = QPushButton("Compare (Head to Head)")
        self.btn_compare.clicked.connect(self.run_compare)
        self.style_btn(self.btn_compare)

        # Layout Arrangement
        analysis_layout.addWidget(QLabel("Driver 1:"), 0, 0)
        analysis_layout.addWidget(self.combo_d1, 0, 1)
        analysis_layout.addWidget(QLabel("Driver 2:"), 0, 2)
        analysis_layout.addWidget(self.combo_d2, 0, 3)
        
        analysis_layout.addWidget(self.btn_results, 1, 0, 1, 4)
        analysis_layout.addWidget(self.btn_telemetry_d1, 2, 0, 1, 2)
        analysis_layout.addWidget(self.btn_telemetry_d2, 2, 2, 1, 2)
        analysis_layout.addWidget(self.btn_compare, 3, 0, 1, 4)

        layout.addLayout(analysis_layout)
        print("<i>[*] System Ready. Select race details above.</i>")

    def style_btn(self, btn, color="#444"):
        """Applies CSS styling to buttons."""
        btn.setStyleSheet(f"""
            QPushButton {{ background-color: {color}; color: white; padding: 12px; font-weight: bold; border-radius: 5px; border: 1px solid #555; }} 
            QPushButton:hover {{ background-color: #666; }}
            QPushButton:pressed {{ background-color: #333; }}
        """)

    # Button Event Handlers (Using Threads to prevent freezing) 
    def run_load(self):
        self.output_log.clear()
        selected_year = self.combo_year.currentText()
        selected_gp = self.combo_gp.currentText()
        selected_session = self.combo_session.currentText()
        threading.Thread(target=lambda: self.engine.load_session(selected_year, selected_gp, selected_session), daemon=True).start()

    def run_results(self):
        self.output_log.clear()
        threading.Thread(target=self.engine.get_results, daemon=True).start()

    def run_telemetry_d1(self):
        self.output_log.clear()
        driver1 = self.combo_d1.currentText()
        threading.Thread(target=lambda: self.engine.analyze_driver(driver1), daemon=True).start()

    def run_telemetry_d2(self):
        self.output_log.clear()
        driver2 = self.combo_d2.currentText()
        threading.Thread(target=lambda: self.engine.analyze_driver(driver2), daemon=True).start()

    def run_compare(self):
        self.output_log.clear()
        driver1 = self.combo_d1.currentText()
        driver2 = self.combo_d2.currentText()
        threading.Thread(target=lambda: self.engine.compare_drivers(driver1, driver2), daemon=True).start()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = F1AnalyzerGUI()
    window.show()
    sys.exit(app.exec())