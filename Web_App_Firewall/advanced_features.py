#!/usr/bin/env python3
"""
Advanced WAF Features
- Pattern learning from attack logs
- Attack analytics and visualization
- Custom rule management
"""

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
import os


class AttackAnalyzer:
    """Analyze attack patterns from logs"""
    
    def __init__(self, log_file='waf.log'):
        self.log_file = log_file
        self.attacks = []
    
    def load_attacks(self):
        """Load attacks from log file"""
        if not os.path.exists(self.log_file):
            print(f"Log file {self.log_file} not found")
            return
        
        with open(self.log_file, 'r') as f:
            for line in f:
                if 'Attack detected' in line:
                    # Parse log line
                    # Format: YYYY-MM-DD HH:MM:SS - WARNING - Attack detected from IP: THREAT_TYPE
                    try:
                        parts = line.split(' - ')
                        timestamp_str = parts[0].strip()
                        message = parts[2].strip() if len(parts) > 2 else ""
                        
                        if 'from' in message:
                            ip_part = message.split('from ')[1].split(':')[0]
                            threat_part = message.split(': ')[1] if ': ' in message else ""
                            
                            self.attacks.append({
                                'timestamp': timestamp_str,
                                'ip': ip_part,
                                'threats': threat_part.split(', ')
                            })
                    except Exception as e:
                        continue
    
    def get_attack_timeline(self, hours=24):
        """Get attack frequency over time"""
        timeline = defaultdict(int)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        for attack in self.attacks:
            try:
                attack_time = datetime.strptime(attack['timestamp'], '%Y-%m-%d %H:%M:%S')
                if attack_time >= cutoff:
                    hour_key = attack_time.strftime('%Y-%m-%d %H:00')
                    timeline[hour_key] += 1
            except:
                continue
        
        return dict(sorted(timeline.items()))
    
    def get_top_attackers(self, limit=10):
        """Get most active attacking IPs"""
        ip_counter = Counter(attack['ip'] for attack in self.attacks)
        return ip_counter.most_common(limit)
    
    def get_threat_distribution(self):
        """Get distribution of threat types"""
        all_threats = []
        for attack in self.attacks:
            all_threats.extend(attack['threats'])
        return Counter(all_threats)
    
    def detect_attack_patterns(self):
        """Detect patterns in attacks"""
        patterns = {
            'coordinated_attacks': [],
            'repeated_targets': [],
            'attack_bursts': []
        }
        
        # Detect coordinated attacks (multiple IPs attacking within short time)
        time_windows = defaultdict(list)
        for attack in self.attacks:
            try:
                attack_time = datetime.strptime(attack['timestamp'], '%Y-%m-%d %H:%M:%S')
                window_key = attack_time.strftime('%Y-%m-%d %H:%M')
                time_windows[window_key].append(attack['ip'])
            except:
                continue
        
        for window, ips in time_windows.items():
            if len(set(ips)) >= 3:  # 3+ unique IPs in same minute
                patterns['coordinated_attacks'].append({
                    'time': window,
                    'unique_ips': len(set(ips)),
                    'total_attacks': len(ips)
                })
        
        # Detect repeated targets (same IP attacking multiple times)
        ip_attacks = defaultdict(int)
        for attack in self.attacks:
            ip_attacks[attack['ip']] += 1
        
        for ip, count in ip_attacks.items():
            if count >= 10:
                patterns['repeated_targets'].append({
                    'ip': ip,
                    'attack_count': count
                })
        
        return patterns
    
    def generate_report(self, output_file='attack_report.txt'):
        """Generate comprehensive attack report"""
        self.load_attacks()
        
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("WAF ATTACK ANALYSIS REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"\nReport Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Total Attacks Analyzed: {len(self.attacks)}\n")
        
        # Top Attackers
        report_lines.append("\n" + "=" * 70)
        report_lines.append("TOP 10 ATTACKING IPs")
        report_lines.append("=" * 70)
        top_attackers = self.get_top_attackers()
        for i, (ip, count) in enumerate(top_attackers, 1):
            report_lines.append(f"{i}. {ip:20s} - {count:5d} attacks")
        
        # Threat Distribution
        report_lines.append("\n" + "=" * 70)
        report_lines.append("THREAT TYPE DISTRIBUTION")
        report_lines.append("=" * 70)
        threat_dist = self.get_threat_distribution()
        for threat, count in threat_dist.most_common():
            percentage = (count / len(self.attacks)) * 100 if self.attacks else 0
            report_lines.append(f"{threat:30s} - {count:5d} ({percentage:5.1f}%)")
        
        # Attack Timeline
        report_lines.append("\n" + "=" * 70)
        report_lines.append("ATTACK TIMELINE (Last 24 Hours)")
        report_lines.append("=" * 70)
        timeline = self.get_attack_timeline()
        for time, count in timeline.items():
            bar = '#' * (count // 2) if count > 0 else ''
            report_lines.append(f"{time} - {count:4d} attacks {bar}")
        
        # Attack Patterns
        report_lines.append("\n" + "=" * 70)
        report_lines.append("DETECTED ATTACK PATTERNS")
        report_lines.append("=" * 70)
        patterns = self.detect_attack_patterns()
        
        if patterns['coordinated_attacks']:
            report_lines.append("\nCoordinated Attacks Detected:")
            for attack in patterns['coordinated_attacks'][:5]:
                report_lines.append(f"  - {attack['time']}: {attack['unique_ips']} IPs, {attack['total_attacks']} attacks")
        
        if patterns['repeated_targets']:
            report_lines.append("\nPersistent Attackers:")
            for target in patterns['repeated_targets'][:5]:
                report_lines.append(f"  - {target['ip']}: {target['attack_count']} attacks")
        
        # Recommendations
        report_lines.append("\n" + "=" * 70)
        report_lines.append("SECURITY RECOMMENDATIONS")
        report_lines.append("=" * 70)
        
        if patterns['coordinated_attacks']:
            report_lines.append("⚠ Coordinated attacks detected - Consider implementing geo-blocking")
        
        if threat_dist.get('SQL_INJECTION', 0) > 10:
            report_lines.append("⚠ High SQL injection attempts - Review database input validation")
        
        if threat_dist.get('XSS', 0) > 10:
            report_lines.append("⚠ High XSS attempts - Implement Content Security Policy (CSP)")
        
        if threat_dist.get('RATE_LIMIT_EXCEEDED', 0) > 50:
            report_lines.append("⚠ Many rate limit violations - Consider stricter limits")
        
        report_lines.append("\n" + "=" * 70)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 70)
        
        # Write report
        report_text = '\n'.join(report_lines)
        with open(output_file, 'w') as f:
            f.write(report_text)
        
        print(report_text)
        print(f"\nReport saved to: {output_file}")


class CustomRuleManager:
    """Manage custom security rules"""
    
    def __init__(self, rules_file='custom_rules.json'):
        self.rules_file = rules_file
        self.rules = self.load_rules()
    
    def load_rules(self):
        """Load custom rules from file"""
        if os.path.exists(self.rules_file):
            with open(self.rules_file, 'r') as f:
                return json.load(f)
        return {
            'patterns': [],
            'blacklisted_ips': [],
            'whitelisted_paths': []
        }
    
    def save_rules(self):
        """Save rules to file"""
        with open(self.rules_file, 'w') as f:
            json.dump(self.rules, indent=2, fp=f)
    
    def add_pattern(self, name, pattern, description=''):
        """Add a custom detection pattern"""
        self.rules['patterns'].append({
            'name': name,
            'pattern': pattern,
            'description': description,
            'created': datetime.now().isoformat()
        })
        self.save_rules()
        print(f"Added pattern: {name}")
    
    def add_blacklisted_ip(self, ip, reason=''):
        """Add IP to blacklist"""
        self.rules['blacklisted_ips'].append({
            'ip': ip,
            'reason': reason,
            'added': datetime.now().isoformat()
        })
        self.save_rules()
        print(f"Blacklisted IP: {ip}")
    
    def add_whitelisted_path(self, path):
        """Add path to whitelist (bypass WAF checks)"""
        if path not in self.rules['whitelisted_paths']:
            self.rules['whitelisted_paths'].append(path)
            self.save_rules()
            print(f"Whitelisted path: {path}")
    
    def list_rules(self):
        """Display all custom rules"""
        print("\n" + "=" * 60)
        print("CUSTOM SECURITY RULES")
        print("=" * 60)
        
        print(f"\nCustom Patterns ({len(self.rules['patterns'])}):")
        for rule in self.rules['patterns']:
            print(f"  - {rule['name']}: {rule['pattern']}")
            if rule.get('description'):
                print(f"    Description: {rule['description']}")
        
        print(f"\nBlacklisted IPs ({len(self.rules['blacklisted_ips'])}):")
        for item in self.rules['blacklisted_ips']:
            print(f"  - {item['ip']}: {item.get('reason', 'No reason provided')}")
        
        print(f"\nWhitelisted Paths ({len(self.rules['whitelisted_paths'])}):")
        for path in self.rules['whitelisted_paths']:
            print(f"  - {path}")


def main():
    """Main menu for advanced features"""
    print("\n" + "=" * 60)
    print("WAF ADVANCED FEATURES")
    print("=" * 60)
    print("\n1. Generate Attack Analysis Report")
    print("2. Manage Custom Rules")
    print("3. View Attack Statistics")
    print("4. Exit")
    
    choice = input("\nSelect option (1-4): ").strip()
    
    if choice == '1':
        analyzer = AttackAnalyzer()
        analyzer.generate_report()
    
    elif choice == '2':
        rule_manager = CustomRuleManager()
        print("\n1. List all rules")
        print("2. Add custom pattern")
        print("3. Blacklist IP")
        print("4. Whitelist path")
        
        sub_choice = input("\nSelect option: ").strip()
        
        if sub_choice == '1':
            rule_manager.list_rules()
        elif sub_choice == '2':
            name = input("Pattern name: ")
            pattern = input("Regex pattern: ")
            description = input("Description (optional): ")
            rule_manager.add_pattern(name, pattern, description)
        elif sub_choice == '3':
            ip = input("IP address: ")
            reason = input("Reason: ")
            rule_manager.add_blacklisted_ip(ip, reason)
        elif sub_choice == '4':
            path = input("Path to whitelist: ")
            rule_manager.add_whitelisted_path(path)
    
    elif choice == '3':
        analyzer = AttackAnalyzer()
        analyzer.load_attacks()
        
        print("\n" + "=" * 60)
        print("QUICK STATISTICS")
        print("=" * 60)
        print(f"Total attacks: {len(analyzer.attacks)}")
        
        print("\nTop 5 Attackers:")
        for ip, count in analyzer.get_top_attackers(5):
            print(f"  {ip}: {count} attacks")
        
        print("\nThreat Types:")
        for threat, count in analyzer.get_threat_distribution().most_common(5):
            print(f"  {threat}: {count}")


if __name__ == "__main__":
    main()
