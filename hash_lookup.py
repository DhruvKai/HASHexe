#!/usr/bin/env python3
"""
Hash Lookup Tool - Multi-API Threat Intelligence Scanner  
Description: Automates hash lookups across multiple free threat intelligence APIs
Version: 1.5.6 (Enhanced with Adaptive Sandbox + All 7 APIs - Clean Version)
"""

import sys
import argparse
import asyncio
import aiohttp
import json
import time
from typing import Dict, Any
import os
from dotenv import load_dotenv
from colorama import Fore, Style, init
from datetime import datetime, timezone

init(autoreset=True)  # Initialize colorama


class BaseAPI:
    """Base class for all threat intelligence APIs."""
    
    def __init__(self, api_key_env_var: str):
        load_dotenv('config.env')
        self.api_key = os.getenv(api_key_env_var)
        self.session = None
    
    def is_configured(self) -> bool:
        return self.api_key is not None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(limit=10)
            )
        return self.session
    
    async def close_session(self):
        if self.session:
            await self.session.close()


class VirusTotalAPI(BaseAPI):
    """VirusTotal API integration with certificate expiry and timestamp signing info."""
    
    def __init__(self):
        super().__init__('VT_API_KEY')
        self.base_url = 'https://www.virustotal.com/api/v3'
    
    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'x-apikey': self.api_key}
        url = f"{self.base_url}/files/{file_hash}"
        
        async with session.get(url, headers=headers) as response:
            if response.status == 404:
                return {'not_found': True}
            elif response.status == 401:
                raise Exception("Invalid VT_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("VirusTotal rate limit exceeded")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            
            data = await response.json()
            attr = data['data']['attributes']
            
            first_submission_ts = attr.get('first_submission_date')
            last_analysis_ts = attr.get('last_analysis_date')
            first_submission_date = datetime.fromtimestamp(first_submission_ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if first_submission_ts else 'N/A'
            last_analysis_date = datetime.fromtimestamp(last_analysis_ts, timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if last_analysis_ts else 'N/A'
            
            now_ts = int(datetime.now(timezone.utc).timestamp())
            days_since_last_analysis = (now_ts - last_analysis_ts) / 86400 if last_analysis_ts else None
            
            rescan_notice = None
            if days_since_last_analysis and days_since_last_analysis > 30:
                rescan_url = f"{self.base_url}/files/{file_hash}/analyse"
                async with session.post(rescan_url, headers=headers) as rescan_resp:
                    if rescan_resp.status in [200, 201]:
                        rescan_notice = f"Rescan initiated for stale report (last scan {days_since_last_analysis:.0f} days ago). Refresh the report link shortly."
                    else:
                        rescan_notice = f"Failed to initiate rescan (HTTP {rescan_resp.status}). "
            
            stats = attr.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            result = {
                'malicious': malicious > 0,
                'detection_ratio': f"{malicious}/{total} engines",
                'report_link': f"https://www.virustotal.com/gui/file/{file_hash}",
                'first_submission_date': first_submission_date,
                'last_analysis_date': last_analysis_date,
                'rescan_notice': rescan_notice
            }
            
            if malicious > 0:
                engines = attr.get('last_analysis_results', {})
                threats = [res['result'] for res in engines.values() if res['category'] == 'malicious' and res['result']]
                if threats:
                    result['signature'] = threats[0]
            
            sig_info = attr.get('signature_info', {})
            signers_details = (sig_info.get('signers details') or 
                             sig_info.get('signers-details') or 
                             sig_info.get('signers') or [])
            
            def format_cert_info(cert):
                if not cert:
                    return {'Issuer': 'N/A', 'Valid From': 'N/A', 'Valid To': 'N/A', 'Expiry Notice': None}
                
                issuer = cert.get('cert issuer') or cert.get('cert_issuer') or 'N/A'
                valid_from = cert.get('valid from') or cert.get('valid_from') or 'N/A'
                valid_to = cert.get('valid to') or cert.get('valid_to') or 'N/A'
                expiry_notice = None
                
                try:
                    valid_to_dt = datetime.strptime(valid_to, '%I:%M %p %m/%d/%Y').replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    if now > valid_to_dt:
                        delta = now - valid_to_dt
                        expiry_notice = f"Certificate expired {delta.days} days ago"
                    else:
                        delta = valid_to_dt - now
                        expiry_notice = f"Certificate valid for {delta.days} more days"
                except:
                    expiry_notice = "Unable to parse certificate validity dates"
                
                return {
                    'Issuer': issuer,
                    'Valid From': valid_from,
                    'Valid To': valid_to,
                    'Expiry Notice': expiry_notice
                }
            
            code_signing_cert = None
            timestamp_signing_cert = None
            
            for signer in signers_details:
                usage = signer.get('valid usage', '').lower() or signer.get('valid_usage', '').lower()
                if 'code signing' in usage and not code_signing_cert:
                    code_signing_cert = signer
                elif 'timestamp signing' in usage and not timestamp_signing_cert:
                    timestamp_signing_cert = signer
            
            result['code_signing_cert_info'] = format_cert_info(code_signing_cert)
            result['timestamp_signing_cert_info'] = format_cert_info(timestamp_signing_cert)
            
            return result


class MetaDefenderAPI(BaseAPI):
    def __init__(self):
        super().__init__('METADEFENDER_API_KEY')
        self.base_url = 'https://api.metadefender.com/v4'

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'apikey': self.api_key}
        url = f"{self.base_url}/hash/{file_hash}"
        
        async with session.get(url, headers=headers) as response:
            if response.status == 404:
                return {
                    'malicious': False,
                    'scan_result': 'Not found in API - check web interface',
                    'detection_ratio': 'Unknown',
                    'sandbox_result': 'Not analyzed',
                    'report_link': f'https://metadefender.com/results/hash/{file_hash.upper()}'
                }
            elif response.status == 401:
                raise Exception("Invalid METADEFENDER_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("MetaDefender API rate limit exceeded")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            
            data = await response.json()
            
            # Process traditional scan details
            engine_results = data.get('scan_results', {}).get('scan_details', {})
            if engine_results:
                total_engines = len(engine_results)
                threats = [v.get('threat_found') for v in engine_results.values() if v.get('threat_found')]
                detections = len(threats)
                detection_ratio = f"{detections}/{total_engines} engines"
                
                if detections > 0:
                    scan_is_malicious = True
                    scan_result = data.get('scan_all_result_i') or f"{detections} threats detected"
                else:
                    scan_is_malicious = False
                    scan_result = data.get('scan_all_result_i') or "No Threat Detected"
            else:
                total_engines = 0
                threats = []
                detections = 0
                detection_ratio = 'Unknown'
                scan_is_malicious = False
                scan_result = 'Check web interface'
            
            # ENHANCED: Process Adaptive Sandbox results
            sandbox_result = "Not analyzed"
            sandbox_is_malicious = False
            sandbox_details = []
            
            # Check for process_info (Dynamic Analysis/Sandbox)
            process_info = data.get('process_info', {})
            if process_info:
                # Check for sandbox verdict
                sandbox_verdict = (
                    process_info.get('verdict') or 
                    process_info.get('sandbox_verdict') or
                    process_info.get('dynamic_verdict')
                )
                
                if sandbox_verdict:
                    sandbox_verdict_lower = sandbox_verdict.lower()
                    if 'malicious' in sandbox_verdict_lower or 'suspicious' in sandbox_verdict_lower:
                        sandbox_is_malicious = True
                        sandbox_result = f"Likely Malicious ({sandbox_verdict})"
                    elif 'clean' in sandbox_verdict_lower or 'benign' in sandbox_verdict_lower:
                        sandbox_result = f"Clean ({sandbox_verdict})"
                    else:
                        sandbox_result = f"Analyzed ({sandbox_verdict})"
                else:
                    sandbox_result = "Analyzed - check web interface"
                
                # Extract behavioral indicators
                behaviors = process_info.get('behaviors', [])
                if behaviors:
                    sandbox_details.extend(behaviors[:3])  # Limit to first 3 behaviors
                
                # Check for network activity
                network_info = process_info.get('network', {})
                if network_info.get('dns_requests') or network_info.get('http_requests'):
                    sandbox_details.append("Network activity detected")
            
            # Check sanitization info (another sandbox result location)
            sanitization = data.get('sanitization', {})
            if sanitization and not process_info:
                sanitization_result = sanitization.get('result')
                if sanitization_result:
                    if sanitization_result.lower() in ['malicious', 'suspicious']:
                        sandbox_is_malicious = True
                        sandbox_result = f"Sanitization: {sanitization_result}"
                    else:
                        sandbox_result = f"Sanitization: {sanitization_result}"
            
            # Determine overall malicious status (combining scan engines + sandbox)
            overall_malicious = scan_is_malicious or sandbox_is_malicious
            
            # Create enhanced summary
            summary = {
                'malicious': overall_malicious,
                'detection_ratio': detection_ratio,
                'scan_result': scan_result,
                'sandbox_result': sandbox_result,
                'report_link': f'https://metadefender.com/results/hash/{file_hash.upper()}'
            }
            
            # Add traditional engine threats
            if threats:
                summary['signature'] = threats[0]
            
            # Add sandbox behavioral details
            if sandbox_details:
                summary['sandbox_behaviors'] = sandbox_details[:2]  # Top 2 behaviors
            
            # Add file info if available
            if data.get('file_info'):
                file_info = data['file_info']
                if file_info.get('display_name'):
                    summary['filename'] = file_info['display_name']
                if file_info.get('file_type_description'):
                    summary['file_type'] = file_info['file_type_description']
            
            return summary


class OTXAlienVaultAPI(BaseAPI):
    def __init__(self):
        super().__init__('OTX_API_KEY')
        self.base_url = 'https://otx.alienvault.com/api/v1'
    
    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'X-OTX-API-KEY': self.api_key}
        url = f"{self.base_url}/indicators/file/{file_hash}/general"
        
        async with session.get(url, headers=headers) as response:
            if response.status == 404:
                return {'not_found': True}
            elif response.status == 401:
                raise Exception("Invalid OTX_API_KEY in config.env")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            
            data = await response.json()
            pulse_info = data.get('pulse_info', {})
            pulse_count = pulse_info.get('count', 0)
            
            result = {
                'malicious': pulse_count > 0,
                'context': f"Associated with {pulse_count} threat reports" if pulse_count > 0 else "No threat reports",
                'report_link': f"https://otx.alienvault.com/indicator/file/{file_hash}"
            }
            
            if pulse_count > 0:
                pulses = pulse_info.get('pulses', [])
                if pulses:
                    result['threat_name'] = pulses[0].get('name', 'Unknown')
            
            return result


class MalwareBazaarAPI(BaseAPI):
    """MalwareBazaar API integration."""
    
    def __init__(self):
        super().__init__('MB_API_KEY')
        self.base_url = 'https://mb-api.abuse.ch/api/v1/'

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {'Auth-Key': self.api_key}
        data = {
            'query': 'get_info',
            'hash': file_hash
        }
        
        async with session.post(self.base_url, headers=headers, data=data) as response:
            if response.status == 401:
                raise Exception("🔐 Invalid MB_API_KEY in config.env")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            
            result_data = await response.json()
            
            if result_data.get('query_status') == 'hash_not_found':
                return {'not_found': True}
            elif result_data.get('query_status') != 'ok':
                raise Exception(f"API Error: {result_data.get('query_status')}")
            
            sample_data = result_data.get('data', [])
            if not sample_data:
                return {'not_found': True}
            
            sample = sample_data[0]
            
            result = {
                'malicious': True,
                'signature': sample.get('signature', 'Unknown'),
                'threat_name': sample.get('signature', 'Unknown'),
                'report_link': f"https://bazaar.abuse.ch/sample/{sample.get('sha256_hash', file_hash)}"
            }
            
            return result

class ThreatFoxAPI(BaseAPI):
    """ThreatFox API integration."""
    
    def __init__(self):
        super().__init__('THREATFOX_API_KEY')
        self.base_url = 'https://threatfox-api.abuse.ch/api/v1/'

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {
            'Auth-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        payload = {
            'query': 'search_hash',
            'hash': file_hash
        }
        
        async with session.post(self.base_url, headers=headers, json=payload) as response:
            if response.status == 401:
                raise Exception("🔐 Invalid THREATFOX_API_KEY in config.env")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            
            result_data = await response.json()
            
            if result_data.get('query_status') == 'no_result':
                return {'not_found': True}
            elif result_data.get('query_status') == 'illegal_hash':
                raise Exception("Invalid hash format provided")
            elif result_data.get('query_status') != 'ok':
                raise Exception(f"API Error: {result_data.get('query_status')}")
            
            iocs = result_data.get('data', [])
            if not iocs:
                return {'not_found': True}
            
            ioc = iocs[0]
            
            result = {
                'malicious': True,
                'signature': ioc.get('malware', 'Unknown'),
                'threat_name': ioc.get('malware', 'Unknown'),
                'context': f"IOC Type: {ioc.get('ioc_type', 'Unknown')}",
                'report_link': f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}"
            }
            
            return result


class HybridAnalysisAPI(BaseAPI):
    def __init__(self):
        super().__init__('HYBRID_API_KEY')
        self.base_url = 'https://www.hybrid-analysis.com/api/v2'

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        session = await self._get_session()
        headers = {
            'api-key': self.api_key,
            'User-Agent': 'Falcon Sandbox'
        }
        url = f"{self.base_url}/search/hash"
        params = {'hash': file_hash}
        
        async with session.get(url, headers=headers, params=params) as response:
            if response.status == 404:
                return {'not_found': True}
            elif response.status == 401:
                raise Exception("Invalid HYBRID_API_KEY in config.env")
            elif response.status == 429:
                raise Exception("Rate limit exceeded.")
            elif response.status != 200:
                error_text = await response.text()
                raise Exception(f"HTTP {response.status}: {error_text}")
            
            data = await response.json()
            
            if not data or not data.get('reports'):
                return {
                    'malicious': False,
                    'context': 'No detailed report available via API. Please check the web UI for the latest info.',
                    'report_link': f"https://www.hybrid-analysis.com/sample/{file_hash}"
                }
            
            # Get the first report
            sample = data['reports'][0] if isinstance(data['reports'], list) and len(data['reports']) > 0 else {}
            
            # FIXED: Handle None verdict properly
            verdict = sample.get('verdict')
            verdict = verdict.lower() if verdict and isinstance(verdict, str) else 'unknown'
            
            threat_score = sample.get('threat_score', 0)
            
            malicious_verdicts = ['malicious', 'suspicious']
            is_malicious = verdict in malicious_verdicts or (threat_score and threat_score > 50)
            
            result = {
                'malicious': is_malicious,
                'context': f"Threat Score: {threat_score}/100" if threat_score else "No threat score available",
                'report_link': f"https://www.hybrid-analysis.com/sample/{file_hash}"
            }
            
            if sample.get('type_short'):
                threat_types = sample['type_short']
                if isinstance(threat_types, list):
                    result['threat_name'] = ', '.join(threat_types)
                else:
                    result['threat_name'] = str(threat_types)
            
            if verdict and verdict != 'unknown':
                result['signature'] = verdict.title()
            
            return result


class TriageSandboxAPI(BaseAPI):
    """Triage Sandbox API integration."""

    def __init__(self):
        super().__init__('TRIAGE_API_KEY')
        self.base_url = 'https://tria.ge/api/v0'

    async def query_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query Triage Sandbox for behavioral analysis."""
        try:
            session = await self._get_session()
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }

            # Search for analyses by hash
            search_url = f"{self.base_url}/search"
            search_params = {'query': f'sha256:{file_hash}'}

            async with session.get(search_url, headers=headers, params=search_params) as response:
                if response.status == 401:
                    raise Exception("Invalid TRIAGE_API_KEY in config.env")
                elif response.status == 429:
                    raise Exception("Triage API rate limit exceeded")
                elif response.status != 200:
                    error_text = await response.text()
                    raise Exception(f"HTTP {response.status}: {error_text}")

                search_data = await response.json()

            # Check if we have data
            if (not search_data or 
                'data' not in search_data or 
                search_data['data'] is None or 
                len(search_data['data']) == 0):

                return {
                    'not_found': True,
                    'report_link': f'https://tria.ge/s?q=sha256:{file_hash}',
                    'context': 'No analysis found - file may not have been submitted to Triage'
                }

            # Get the latest analysis
            latest_analysis = search_data['data'][0]
            analysis_id = latest_analysis.get('id')

            if not analysis_id:
                return {
                    'not_found': True,
                    'context': 'No valid analysis ID found'
                }

            # Get the overview data
            overview_data = await self._get_overview_data(analysis_id, headers)

            if overview_data.get('error'):
                raise Exception(overview_data['error'])

            return self._format_triage_results(overview_data, analysis_id, latest_analysis)

        except Exception as e:
            raise e

    async def _get_overview_data(self, analysis_id: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Get overview data from Triage."""
        try:
            session = await self._get_session()
            overview_url = f"{self.base_url}/samples/{analysis_id}/overview.json"

            async with session.get(overview_url, headers=headers) as response:
                if response.status != 200:
                    return {'error': f'Failed to get overview data: HTTP {response.status}'}

                return await response.json()

        except Exception as e:
            return {'error': f'Overview data error: {str(e)}'}

    def _format_triage_results(self, overview_data: Dict, analysis_id: str, search_result: Dict) -> Dict[str, Any]:
        """Format Triage results with comprehensive error handling."""

        try:
            if overview_data.get('error'):
                raise Exception(overview_data['error'])

            # Extract safely with defaults
            analysis = overview_data.get('analysis', {})
            sample = overview_data.get('sample', {})
            signatures = overview_data.get('signatures', [])
            extracted = overview_data.get('extracted', [])

            # Extract core data
            score = analysis.get('score', 0)
            family_list = analysis.get('family', [])
            tags = analysis.get('tags', [])

            # Extract target
            target = sample.get('target') or search_result.get('filename', 'Unknown')

            # Extract file info
            file_size = sample.get('size', 'Unknown')
            created = sample.get('created', 'Unknown')

            # Extract configuration data
            c2_servers = []
            config_data = {}

            if extracted and len(extracted) > 0:
                for item in extracted:
                    config = item.get('config', {})
                    if config:
                        config_data = config
                        c2_servers = config.get('c2', [])
                        break

            # Extract behavioral data
            mitre_techniques = []
            behavioral_signatures = []

            for sig in signatures:
                sig_name = sig.get('name', '')
                if sig_name and sig_name not in behavioral_signatures:
                    behavioral_signatures.append(sig_name)

                # Extract MITRE techniques
                ttp = sig.get('ttp', [])
                for technique in ttp:
                    if technique not in mitre_techniques:
                        mitre_techniques.append(technique)

            # Determine threat level
            is_malicious = score >= 5
            if score >= 8:
                threat_level = "High"
            elif score >= 5:
                threat_level = "Medium"
            else:
                threat_level = "Low"

            # Build result
            result = {
                'malicious': is_malicious,
                'score': score,
                'threat_level': threat_level,
                'report_link': f'https://tria.ge/{analysis_id}',
                'analysis_id': analysis_id,
                'target': target,
                'file_size': file_size,
                'analysis_date': created
            }

            # Add family information
            if family_list and len(family_list) > 0:
                result['family'] = family_list[0].title()
                result['family_list'] = family_list

            # Add tags
            if tags and len(tags) > 0:
                clean_tags = []
                for tag in tags:
                    if not tag.startswith('family:'):
                        clean_tags.append(tag.upper())
                if clean_tags:
                    result['tags'] = clean_tags

            # Add behavioral signatures
            if behavioral_signatures:
                result['signatures'] = behavioral_signatures[:10]
                result['signature'] = behavioral_signatures[0]

            # Add MITRE techniques
            if mitre_techniques:
                result['mitre_techniques'] = mitre_techniques[:10]
                result['mitre_summary'] = f"{len(mitre_techniques)} techniques detected"

            # Add network activity
            if c2_servers:
                network_activity = [f"C2: {c2}" for c2 in c2_servers[:5]]
                result['network_activity'] = network_activity
                result['network_summary'] = f"{len(network_activity)} C2 servers detected"

            # Add config
            if config_data:
                result['config'] = {
                    'version': config_data.get('version', 'Unknown'),
                    'mutex': config_data.get('mutex', []),
                    'install_path': config_data.get('attr', {}).get('path_client', 'Unknown')
                }

            # Build context
            context_parts = []
            if family_list and len(family_list) > 0:
                context_parts.append(f"Family: {family_list[0].title()}")
            if behavioral_signatures:
                context_parts.append(f"{len(behavioral_signatures)} behavioral signatures")
            if mitre_techniques:
                context_parts.append(f"{len(mitre_techniques)} MITRE techniques")
            if c2_servers:
                context_parts.append(f"{len(c2_servers)} C2 servers")

            result['context'] = "; ".join(context_parts) if context_parts else "Analysis completed"

            return result

        except Exception as e:
            raise Exception(f'Result formatting error: {str(e)}')

class HashLookupTool:
    def __init__(self):
        load_dotenv('config.env')
        self.apis = {
            'virustotal': VirusTotalAPI(),
            'metadefender': MetaDefenderAPI(),
            'otx': OTXAlienVaultAPI(),
            'malwarebazaar': MalwareBazaarAPI(),
            'threatfox': ThreatFoxAPI(),
            'hybrid_analysis': HybridAnalysisAPI(),
            'triage_sandbox': TriageSandboxAPI(),
        }
    
    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        print('=' * 60)
        print(f"{Fore.CYAN}{Style.BRIGHT}HASH LOOKUP REPORT")
        print('=' * 60)
        print(f"Hash: {file_hash}")
        print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print('=' * 60)
        
        tasks = []
        for api_name, api_instance in self.apis.items():
            if api_instance.is_configured():
                tasks.append(self._query_api(api_name, api_instance, file_hash))
            else:
                print(f"{Fore.YELLOW}{api_name.upper()} API key not configured - skipping")
        
        if not tasks:
            print(f"{Fore.RED}No APIs configured. Please check your config.env file.")
            return {}
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        api_results = {}
        
        for i, (api_name, _) in enumerate(item for item in self.apis.items() if item[1].is_configured()):
            result = results[i]
            if isinstance(result, Exception):
                print(f"{Fore.RED}{api_name.upper()} Error: {str(result)}")
                api_results[api_name] = {'error': str(result)}
            else:
                api_results[api_name] = result
        
        print('=' * 60)
        print(f"{Fore.GREEN}{Style.BRIGHT}SCAN COMPLETE")
        print('=' * 60)
        
        return api_results
    
    async def _query_api(self, api_name: str, api_instance, file_hash: str) -> Dict[str, Any]:
        try:
            result = await api_instance.query_hash(file_hash)
            self.display_result(api_name, result, file_hash)
            return result
        except Exception as e:
            print(f"{Fore.RED}{api_name.upper()} Error: {str(e)}")
            return {'error': str(e)}
    
    def display_result(self, api_name: str, result: Dict[str, Any], file_hash: str) -> None:
        service_name = api_name.replace('_', ' ').title()
        print(f"{Fore.MAGENTA}{Style.BRIGHT}{service_name.upper()}")
        print(f"{Fore.MAGENTA}{'-' * 40}")
        
        if result.get('error'):
            print(f"{Fore.RED}❌ Error: {result['error']}")
        elif result.get('not_found'):
            print(f"{Fore.LIGHTBLACK_EX}ℹ️ Not found in database")
        else:
            # Main malicious status
            if result.get('malicious'):
                print(f"{Fore.RED}{Style.BRIGHT}❌ MALICIOUS")
            else:
                print(f"{Fore.GREEN}{Style.BRIGHT}✔️ Clean/No threat detected")
            
            # Traditional scan results
            if result.get('detection_ratio'):
                print(f"{Fore.YELLOW}🔍 Detections: {Style.BRIGHT}{result['detection_ratio']}")
            
            if result.get('scan_result'):
                print(f"{Fore.CYAN}📊 Scan Result: {Style.BRIGHT}{result['scan_result']}")
            
            # ENHANCED: Show Adaptive Sandbox results for MetaDefender
            if api_name == 'metadefender' and result.get('sandbox_result'):
                sandbox_result = result['sandbox_result']
                if 'Likely Malicious' in sandbox_result:
                    print(f"{Fore.RED}🏥 Adaptive Sandbox: {Style.BRIGHT}{sandbox_result}")
                elif 'Clean' in sandbox_result:
                    print(f"{Fore.GREEN}🏥 Adaptive Sandbox: {Style.BRIGHT}{sandbox_result}")
                elif 'Not analyzed' in sandbox_result:
                    print(f"{Fore.LIGHTBLACK_EX}🏥 Adaptive Sandbox: {sandbox_result}")
                else:
                    print(f"{Fore.YELLOW}🏥 Adaptive Sandbox: {Style.BRIGHT}{sandbox_result}")
            
            # Show sandbox behaviors if available
            if result.get('sandbox_behaviors'):
                behaviors = result['sandbox_behaviors']
                print(f"{Fore.YELLOW}🔬 Behaviors: {Style.BRIGHT}{', '.join(behaviors)}")
            
            # Triage-specific fields
            if result.get('threat_score'):
                print(f"{Fore.YELLOW}📊 Threat Score: {Style.BRIGHT}{result['threat_score']}")
            
            if result.get('target'):
                print(f"{Fore.CYAN}🎯 Target: {Style.BRIGHT}{result['target']}")
            
            if result.get('first_submission_date'):
                print(f"{Fore.CYAN}📅 First Submission Date: {Style.BRIGHT}{result['first_submission_date']}")
            
            if result.get('last_analysis_date'):
                print(f"{Fore.CYAN}📅 Last Analysis Date: {Style.BRIGHT}{result['last_analysis_date']}")
            
            if result.get('rescan_notice'):
                print(f"{Fore.YELLOW}⚠️ {result['rescan_notice']}")
            
            if result.get('signature'):
                print(f"{Fore.YELLOW}🔖 Signature: {Style.BRIGHT}{result['signature']}")
            
            if result.get('filename'):
                print(f"{Fore.CYAN}📄 Filename: {Style.BRIGHT}{result['filename']}")
            
            if result.get('file_type'):
                print(f"{Fore.CYAN}📋 File Type: {Style.BRIGHT}{result['file_type']}")
            
            # Code Signing Certificate
            if result.get('code_signing_cert_info'):
                print(f"{Fore.CYAN}Code Signing Certificate:")
                cert = result['code_signing_cert_info']
                for key in ['Issuer', 'Valid From', 'Valid To']:
                    print(f"{Fore.CYAN}  {key}: {Style.BRIGHT}{cert.get(key, 'N/A')}")
                if cert.get('Expiry Notice'):
                    print(f"{Fore.RED}  ⚠️ {cert['Expiry Notice']}")
            
            # Timestamp Signing Certificate
            if result.get('timestamp_signing_cert_info'):
                print(f"{Fore.CYAN}Timestamp Signing Certificate:")
                cert = result['timestamp_signing_cert_info']
                for key in ['Issuer', 'Valid From', 'Valid To']:
                    print(f"{Fore.CYAN}  {key}: {Style.BRIGHT}{cert.get(key, 'N/A')}")
                if cert.get('Expiry Notice'):
                    print(f"{Fore.RED}  ⚠️ {cert['Expiry Notice']}")
            
            if result.get('threat_name'):
                print(f"{Fore.YELLOW}⚠️ Threat: {Style.BRIGHT}{result['threat_name']}")
            
            if result.get('context'):
                print(f"{Fore.YELLOW}📄 Context: {Style.BRIGHT}{result['context']}")
            
            if result.get('report_link'):
                print(f"{Fore.BLUE}🔗 Report: {Style.BRIGHT}{result['report_link']}")
        
        print()


def _is_valid_hash(hash_string: str) -> bool:
    """Validate hash format (MD5, SHA1, SHA256)"""
    if not hash_string:
        return False
    try:
        int(hash_string, 16)
    except ValueError:
        return False
    return len(hash_string) in [32, 40, 64]


async def main():
    parser = argparse.ArgumentParser(
        description='Hash Lookup Tool - Query multiple threat intelligence APIs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  python hash_lookup.py d41d8cd98f00b204e9800998ecf8427e
  python hash_lookup.py da39a3ee5e6b4b0d3255bfef95601890afd80709
  python hash_lookup.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        '''
    )
    
    parser.add_argument('hash', help='File hash to lookup (MD5, SHA1, or SHA256)')
    parser.add_argument('--version', action='version', version='Hash Lookup Tool v1.5.6')
    
    args = parser.parse_args()
    file_hash = args.hash.strip().lower()
    
    if not _is_valid_hash(file_hash):
        print(f"{Fore.RED}Invalid hash format. Please provide a valid MD5, SHA1, or SHA256 hash.")
        sys.exit(1)
    
    lookup_tool = HashLookupTool()
    
    try:
        await lookup_tool.lookup_hash(file_hash)
        
        for api in lookup_tool.apis.values():
            await api.close_session()
            
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    if sys.version_info < (3, 7):
        print(f"{Fore.RED}This script requires Python 3.7 or higher")
        sys.exit(1)
    
    try:
        import aiohttp
        from dotenv import load_dotenv
        from colorama import Fore, Style, init
    except ImportError as e:
        print(f"{Fore.RED}Missing required dependency: {e.name}")
        print("Please install dependencies: pip install aiohttp python-dotenv colorama")
        sys.exit(1)
    
    init(autoreset=True)
    asyncio.run(main())