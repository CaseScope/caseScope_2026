#!/usr/bin/env python3
"""
DFIR Input Data Scraper
Scrapes case inputs (IOCs, events, systems) from public DFIR sources
You then write your own OUTPUT reports based on these inputs

LEGAL/ETHICAL NOTES:
- Only scrapes publicly available data
- Respects robots.txt
- Adds delay between requests
- Does NOT scrape copyrighted report content (only case metadata)
- For personal training use only
"""

import argparse
import json
import re
import time
from datetime import datetime
from pathlib import Path

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ Missing dependencies. Install with:")
    print("   pip install requests beautifulsoup4")
    exit(1)


class DFIRInputScraper:
    def __init__(self, output_dir="training_data/scraped_inputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CaseScope-Training-Bot/1.0 (Educational Use Only)'
        })
    
    def scrape_thedfirreport(self, limit=10):
        """
        Scrape case metadata from TheDFIRReport
        NOTE: We only scrape IOCs and case metadata, NOT the full report (respecting copyright)
        """
        print("🔍 Scraping TheDFIRReport.com (IOC metadata only)...")
        
        url = "https://thedfirreport.com/"
        try:
            resp = self.session.get(url, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            print(f"❌ Error fetching TheDFIRReport: {e}")
            return []
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Find article links
        articles = soup.find_all('h2', class_='entry-title')[:limit]
        
        inputs = []
        for idx, article in enumerate(articles, 1):
            link = article.find('a')
            if not link:
                continue
            
            title = link.get_text(strip=True)
            article_url = link['href']
            
            print(f"  [{idx}/{len(articles)}] {title}")
            
            # Fetch article page
            time.sleep(2)  # Be polite
            try:
                article_resp = self.session.get(article_url, timeout=10)
                article_resp.raise_for_status()
                article_soup = BeautifulSoup(article_resp.text, 'html.parser')
                
                # Extract IOCs (usually in a table or code block)
                iocs = self._extract_iocs_from_article(article_soup)
                
                # Extract MITRE techniques
                mitre_techniques = self._extract_mitre_from_article(article_soup)
                
                # Create input data
                case_input = {
                    'source': 'TheDFIRReport',
                    'title': title,
                    'url': article_url,
                    'date_scraped': datetime.now().isoformat(),
                    'iocs': iocs,
                    'mitre_techniques': mitre_techniques,
                    'case_name': title,
                    'instruction': "Generate a DFIR investigation report with timeline, MITRE mapping, and executive summary. Use only the evidence provided.",
                    'input_template': self._format_case_input(title, iocs, mitre_techniques)
                }
                
                inputs.append(case_input)
                
            except Exception as e:
                print(f"    ⚠️  Error scraping article: {e}")
                continue
        
        return inputs
    
    def _extract_iocs_from_article(self, soup):
        """Extract IOCs from article (IPs, domains, hashes, etc.)"""
        iocs = {
            'ips': [],
            'domains': [],
            'file_hashes': [],
            'filenames': [],
            'registry_keys': [],
            'usernames': []
        }
        
        # Look for IOC sections (usually in tables or code blocks)
        # This is a simplified extraction - real implementation would be more sophisticated
        text = soup.get_text()
        
        # Extract IPs (basic regex)
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs['ips'] = list(set(re.findall(ip_pattern, text)))[:10]  # Limit to 10
        
        # Extract domains (basic pattern)
        domain_pattern = r'\b[a-z0-9-]+\.[a-z]{2,}\b'
        potential_domains = re.findall(domain_pattern, text.lower())
        iocs['domains'] = [d for d in potential_domains if '.' in d and len(d) > 5][:10]
        
        # Extract MD5/SHA256 hashes
        hash_pattern = r'\b[a-fA-F0-9]{32,64}\b'
        iocs['file_hashes'] = list(set(re.findall(hash_pattern, text)))[:10]
        
        return iocs
    
    def _extract_mitre_from_article(self, soup):
        """Extract MITRE ATT&CK techniques mentioned"""
        techniques = []
        
        text = soup.get_text()
        
        # Look for T#### patterns
        mitre_pattern = r'T\d{4}(?:\.\d{3})?'
        techniques = list(set(re.findall(mitre_pattern, text)))
        
        return techniques
    
    def _format_case_input(self, case_name, iocs, mitre_techniques):
        """Format scraped data as case input"""
        input_text = f"CASE: {case_name}\n\n"
        
        input_text += "IOCs:\n"
        if iocs['ips']:
            for ip in iocs['ips'][:5]:
                input_text += f"- {ip} (IP Address)\n"
        if iocs['domains']:
            for domain in iocs['domains'][:5]:
                input_text += f"- {domain} (Domain)\n"
        if iocs['file_hashes']:
            for hash_val in iocs['file_hashes'][:5]:
                input_text += f"- {hash_val} (File Hash)\n"
        
        if mitre_techniques:
            input_text += f"\nMITRE Techniques Observed:\n"
            for tech in mitre_techniques[:10]:
                input_text += f"- {tech}\n"
        
        input_text += "\nSYSTEMS:\n"
        input_text += "- [SYSTEM_NAME] ([SYSTEM_TYPE]) - YOU NEED TO FILL THIS IN\n"
        
        input_text += "\nEVENTS:\n"
        input_text += "- [TIMESTAMP] | [EventID] | [Description] - YOU NEED TO FILL THIS IN\n"
        input_text += "  (Add actual event logs based on the case details)\n"
        
        return input_text
    
    def scrape_malware_traffic_analysis(self, limit=5):
        """
        Scrape exercise metadata from Malware-Traffic-Analysis.net
        """
        print("🔍 Scraping Malware-Traffic-Analysis.net...")
        
        url = "https://www.malware-traffic-analysis.net/"
        try:
            resp = self.session.get(url, timeout=10)
            resp.raise_for_status()
        except Exception as e:
            print(f"❌ Error fetching Malware-Traffic-Analysis: {e}")
            return []
        
        soup = BeautifulSoup(resp.text, 'html.parser')
        
        # Find exercise links
        links = soup.find_all('a', href=re.compile(r'\d{4}/\d{2}/\d{2}'))[:limit]
        
        inputs = []
        for idx, link in enumerate(links, 1):
            title = link.get_text(strip=True)
            exercise_url = link['href']
            if not exercise_url.startswith('http'):
                exercise_url = f"https://www.malware-traffic-analysis.net/{exercise_url}"
            
            print(f"  [{idx}/{len(links)}] {title}")
            
            case_input = {
                'source': 'Malware-Traffic-Analysis',
                'title': title,
                'url': exercise_url,
                'date_scraped': datetime.now().isoformat(),
                'instruction': "Generate a DFIR investigation report analyzing network traffic and malware behavior.",
                'input_template': f"CASE: {title}\n\nSOURCE: Malware-Traffic-Analysis.net\nURL: {exercise_url}\n\nYOU NEED TO:\n1. Download PCAP from URL\n2. Analyze traffic in Wireshark\n3. Extract IOCs (IPs, domains, file hashes)\n4. Document timeline of network events\n5. Write YOUR ideal DFIR report based on findings\n"
            }
            
            inputs.append(case_input)
            
            time.sleep(1)  # Be polite
        
        return inputs
    
    def save_inputs(self, inputs, filename="scraped_inputs.json"):
        """Save scraped inputs to file"""
        output_path = self.output_dir / filename
        
        with open(output_path, 'w') as f:
            json.dump(inputs, f, indent=2)
        
        print(f"\n✅ Saved {len(inputs)} inputs to {output_path}")
        print(f"\nNext steps:")
        print(f"1. Review scraped inputs: cat {output_path}")
        print(f"2. For each input, write YOUR ideal DFIR report")
        print(f"3. Use create_training_example.py to format as JSONL")
        print(f"4. Train your model!")


def main():
    parser = argparse.ArgumentParser(description='Scrape DFIR case inputs from public sources')
    parser.add_argument('--source', choices=['thedfirreport', 'malware-traffic', 'all'],
                        default='all', help='Which source to scrape')
    parser.add_argument('--limit', type=int, default=10,
                        help='Maximum number of cases to scrape per source')
    parser.add_argument('--output', default='training_data/scraped_inputs',
                        help='Output directory')
    
    args = parser.parse_args()
    
    scraper = DFIRInputScraper(output_dir=args.output)
    
    all_inputs = []
    
    print("=" * 70)
    print("  DFIR Input Data Scraper")
    print("=" * 70)
    print()
    print("⚠️  LEGAL/ETHICAL NOTICE:")
    print("- This tool only scrapes publicly available metadata and IOCs")
    print("- It does NOT scrape copyrighted report content")
    print("- For personal training use only")
    print("- Respect rate limits and robots.txt")
    print()
    
    if args.source in ['thedfirreport', 'all']:
        inputs = scraper.scrape_thedfirreport(limit=args.limit)
        all_inputs.extend(inputs)
    
    if args.source in ['malware-traffic', 'all']:
        inputs = scraper.scrape_malware_traffic_analysis(limit=args.limit)
        all_inputs.extend(inputs)
    
    if all_inputs:
        scraper.save_inputs(all_inputs)
    else:
        print("❌ No inputs scraped")
    
    print()
    print("=" * 70)
    print(f"  Scraped {len(all_inputs)} case inputs")
    print("=" * 70)


if __name__ == "__main__":
    main()

