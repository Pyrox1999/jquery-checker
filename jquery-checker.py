import os
os.environ['SDL_VIDEO_WINDOW_POS'] = '100,100'
import random
import pgzrun
import pygame
import requests
import re
from packaging import version
from datetime import datetime

pygame.mixer.music.load("song.mp3") #SubspaceAudio
pygame.mixer.music.play(-1)

level=-1
url="localhost"
message=""
gemacht=False

class jQueryChecker:
    global message
    def __init__(self):
        self.known_vulnerabilities = {
            "1.6.0": ["CVE-2011-4969: XSS vulnerability"],
            "1.7.0": ["CVE-2011-4969: XSS vulnerability"],
            "1.8.0": ["CVE-2012-6708: Selector injection"],
            "1.9.0": ["CVE-2012-6708: Selector injection"],
            "1.11.0": ["CVE-2015-9251: XSS vulnerability"],
            "1.12.0": ["CVE-2015-9251: XSS vulnerability"],
            "2.0.0": ["CVE-2015-9251: XSS vulnerability"],
            "2.1.0": ["CVE-2015-9251: XSS vulnerability"],
            "2.2.0": ["CVE-2015-9251: XSS vulnerability"],
            "3.0.0": ["CVE-2019-11358: Prototype pollution", "CVE-2020-11022: XSS"],
            "3.1.0": ["CVE-2019-11358: Prototype pollution", "CVE-2020-11022: XSS"],
            "3.2.0": ["CVE-2019-11358: Prototype pollution", "CVE-2020-11022: XSS"],
            "3.3.0": ["CVE-2019-11358: Prototype pollution", "CVE-2020-11022: XSS"],
            "3.4.0": ["CVE-2020-11022: XSS vulnerability"],
        }
        
        self.latest_stable = "3.7.1"  
        self.min_safe_version = "3.5.0"  
    
    def check_website(self, url):
        global message
        message+=f"\n{'='*70}\n"
        message+=f"🔍 jQuery Security Check for: {url}\n"
        message+=f"{'='*70}\n\n"
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            html = response.text
            
            jquery_found = self.find_jquery(html, url)
            
            if not jquery_found:
                message+="❌ jQuery was not found on this site.\n"
                message+="Maybe because:\n"
                message+="  • this page doesn't use jQuery\n"
                message+="  • jQuery is loaded dynamic\n"
                message+="  • jQuery is minimal/obfuscated\n"
                return
            
            for jquery_info in jquery_found:
                self.analyze_version(jquery_info)
                
        except requests.RequestException as e:
            message+=f"❌ Error in loadng URL: {e}\n"
    
    def find_jquery(self, html, base_url):
        jquery_matches = []
        
        patterns = [
            r'<script[^>]+src=["\']([^"\']*jquery[^"\']*)["\']',
            r'jQuery[^\d]*([\d]+\.[\d]+\.[\d]+)',
            r'\$\.fn\.jquery\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                jquery_matches.append(match.group(1))
        
        versions_found = []
        for match in jquery_matches:
            version_match = re.search(r'([\d]+\.[\d]+\.[\d]+)', match)
            if version_match:
                ver = version_match.group(1)
                src = match if 'http' in match or '/' in match else 'Inline'
                versions_found.append({
                    'version': ver,
                    'source': src
                })
        
        seen = set()
        unique_versions = []
        for item in versions_found:
            if item['version'] not in seen:
                seen.add(item['version'])
                unique_versions.append(item)
        
        return unique_versions
    
    def analyze_version(self, jquery_info):
        global message
        ver = jquery_info['version']
        src = jquery_info['source']
        
        message+=f"\n{'─'*70}\n"
        message+=f"📦 jQuery was found!\n"
        message+=f"{'─'*70}\n"
        message+=f"Version: {ver}\n"
        message+=f"Quelle: {src[:80]}{'...' if len(src) > 80 else ''}\n"
        
        try:
            current_ver = version.parse(ver)
            latest_ver = version.parse(self.latest_stable)
            min_safe_ver = version.parse(self.min_safe_version)
            
            message+=f"\nLatest Version: {self.latest_stable}\n"
            
            if current_ver >= latest_ver:
                message+="✅ Status: ACTUALLY\n"
            elif current_ver >= min_safe_ver:
                message+="⚠️  Status: OLDER (but relative secure)\n"
                message+=f"   Recommendation: Update on {self.latest_stable}\n"
            else:
                message+="🔴 Status: VERY OLD & DANGEROUS!\n"
                message+=f"   URGENT: Update on {self.latest_stable} required!\n"
            
            vulnerabilities = []
            for vuln_ver, vulns in self.known_vulnerabilities.items():
                if current_ver <= version.parse(vuln_ver):
                    vulnerabilities.extend(vulns)
            
            if vulnerabilities:
                message+=f"\n🚨 KNOWN VILNERABILITIES:\n"
                seen_cves = set()
                for vuln in vulnerabilities:
                    if vuln not in seen_cves:
                        message+=f"   • {vuln}"
                        seen_cves.add(vuln)
            else:
                message+="\n✓ No known critical weak points\n"
            
    
            risk_score = self.calculate_risk(current_ver)
            message+=f"\n{'─'*70}\n"
            message+=f"Risk-Score: {risk_score}/100\n"
            
            if risk_score >= 80:
                message+="🔴 CRITICAL RISK - urgently fix requeired!\n"
            elif risk_score >= 60:
                message+="🟠 HIGH RISK - Update urgently recommended\n"
            elif risk_score >= 40:
                message+="🟡 MEDIUM RISK - Update recommended\n"
            elif risk_score >= 20:
                message+="🟢 SMALL RISK - Update when you have time\n"
            else:
                message+="✅ VERY SMALL RISK\n"
            
        except Exception as e:
            message+=f"⚠️  Error during the parsing of that version: {e}\n"
    
    def calculate_risk(self, ver):
        
        score = 0
        
        latest_ver = version.parse(self.latest_stable)
        min_safe_ver = version.parse(self.min_safe_version)
        
    
        if ver < version.parse("2.0.0"):
            score += 50  
        elif ver < version.parse("3.0.0"):
            score += 30
        elif ver < min_safe_ver:
            score += 20
        
        
        for vuln_ver in self.known_vulnerabilities.keys():
            if ver <= version.parse(vuln_ver):
                score += 10
        
        
        major_diff = latest_ver.major - ver.major
        score += major_diff * 15
        
        return min(100, score)
    
    def check_cdn_integrity(self, html):
        global message
        sri_pattern = r'<script[^>]+src=["\'][^"\']*jquery[^"\']*["\'][^>]+integrity='
        has_sri = bool(re.search(sri_pattern, html, re.IGNORECASE))
        
        if has_sri:
            message+="\n✓ Subresource Integrity (SRI) is used\n"
        else:
            message+="\n⚠️  No Subresource Integrity (SRI) found\n"
            message+="   Recommendation: Use SRI-Hashes for CDN-Ressources\n"

def draw():
    global level, url,message
    screen.clear()
    if level == -1:
        screen.blit("title", (0, 0))
    elif level == 0:
        screen.blit("intro", (0, 0))
    elif level == 1:
        screen.blit("back", (0, 0))
        screen.draw.text("Website to scan:", center=(400, 130), fontsize=24, color=(25, 200, 255))
        screen.draw.text(url, center=(400, 180), fontsize=24, color=(255, 255, 0))
    elif level == 2:
        screen.blit("back",(0,0))
        screen.draw.text(message, center=(400, 180), fontsize=24, color=(255, 255, 0))

def on_key_down(key, unicode=None):
    global level, url
    if key==keys.ESCAPE:
        pygame.quit()
    if key == keys.BACKSPACE:
        url = ""
    elif key == keys.RETURN and level == 1:
        level = 2
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
    elif unicode and key != keys.RETURN and level==1:
        url += unicode

def update():
    global level,checker,gemacht
    if (level == 0 or level==-2) and keyboard.RETURN:
        level +=1
    elif level -1 and keyboard.space:
        level = 0
    if level==1:
        checker = jQueryChecker()
    if level==2:
        if not gemacht:
            checker.check_website(url)
            gemacht=True
        if keyboard.space:
            level=0

pgzrun.go()
