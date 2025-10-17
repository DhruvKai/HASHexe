from fastapi import FastAPI, Request, Form, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import asyncio
import csv
import io
import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import os
import sys
from urllib.parse import urlparse
import base64
import uuid
import time


# Import your existing hash lookup tool
from hash_lookup import HashLookupTool, _is_valid_hash


class InMemoryStorage:
    """In-memory storage for history, bookmarks, and sessions."""
    
    def __init__(self):
        self.search_history = []
        self.bookmarks = []
        self.bulk_sessions = {}
        self.api_health_cache = {}
        self.max_history = 100
    
    def add_search_history(self, search_type: str, search_value: str, results_summary: str = None, threat_score: int = 0):
        """Add search to history."""
        entry = {
            'type': search_type,
            'value': search_value,
            'timestamp': datetime.now().isoformat(),
            'summary': results_summary or 'No summary',
            'threat_score': threat_score
        }
        
        self.search_history.insert(0, entry)
        
        # Keep only last max_history entries
        if len(self.search_history) > self.max_history:
            self.search_history = self.search_history[:self.max_history]
    
    def get_search_history(self, limit: int = 20) -> List[Dict]:
        """Get recent search history."""
        return self.search_history[:limit]
    
    def add_bookmark(self, search_type: str, search_value: str, title: str = None, notes: str = "") -> bool:
        """Add bookmark."""
        # Check if already bookmarked
        for bookmark in self.bookmarks:
            if bookmark['value'] == search_value:
                return False
        
        bookmark = {
            'type': search_type,
            'value': search_value,
            'title': title or search_value[:32],
            'notes': notes,
            'threat_score': 0,
            'created_at': datetime.now().isoformat()
        }
        
        self.bookmarks.insert(0, bookmark)
        return True
    
    def get_bookmarks(self) -> List[Dict]:
        """Get all bookmarks."""
        return self.bookmarks
    
    def remove_bookmark(self, search_value: str) -> bool:
        """Remove bookmark."""
        for i, bookmark in enumerate(self.bookmarks):
            if bookmark['value'] == search_value:
                del self.bookmarks[i]
                return True
        return False

class ThreatAnalyzer:
    """Enhanced threat analysis and scoring."""
    
    @staticmethod
    def calculate_threat_score(results: Dict[str, Any]) -> int:
        """Calculate overall threat score (0-100)."""
        scores = []
        total_apis = 0
        malicious_count = 0
        
        for api_name, result in results.items():
            if isinstance(result, dict) and not result.get('error') and not result.get('not_found'):
                total_apis += 1
                if result.get('malicious', False):
                    malicious_count += 1
                    
                    # Weight scores based on API reliability
                    api_weights = {
                        'virustotal': 30,
                        'crowdstrike': 25,
                        'triage_sandbox': 20,
                        'hybrid_analysis': 15,
                        'malwarebazaar': 10,
                        'threatfox': 10,
                        'metadefender': 8,
                        'otx': 5
                    }
                    scores.append(api_weights.get(api_name, 10))
        
        if total_apis == 0:
            return 0
        
        # Calculate confidence based on consensus
        confidence = malicious_count / total_apis
        base_score = sum(scores)
        
        # Apply confidence multiplier
        final_score = min(100, int(base_score * confidence * 1.2))
        
        return final_score
    
    @staticmethod
    def generate_summary(results: Dict[str, Any]) -> str:
        """Generate human-readable threat summary."""
        threat_score = ThreatAnalyzer.calculate_threat_score(results)
        
        malicious_apis = []
        clean_apis = []
        error_apis = []
        
        for api_name, result in results.items():
            if isinstance(result, dict):
                if result.get('error'):
                    error_apis.append(api_name)
                elif result.get('not_found'):
                    continue
                elif result.get('malicious', False):
                    malicious_apis.append(api_name)
                else:
                    clean_apis.append(api_name)
        
        total_checked = len(malicious_apis) + len(clean_apis)
        
        if threat_score >= 80:
            level = "🚨 HIGH THREAT"
        elif threat_score >= 50:
            level = "⚠️ MODERATE THREAT"
        elif threat_score >= 20:
            level = "🔍 LOW THREAT"
        else:
            level = "✅ CLEAN"
        
        summary = f"{level} (Score: {threat_score}/100) - {len(malicious_apis)}/{total_checked} APIs detected threats"
        
        return summary

class BulkProcessor:
    """Handle bulk hash/URL processing."""
    
    def __init__(self, storage: InMemoryStorage):
        self.storage = storage
    
    async def process_csv(self, file_content: str, session_id: str) -> Dict[str, Any]:
        """Process CSV file with hashes/URLs."""
        results = []
        items = []
        
        # Parse CSV content
        csv_reader = csv.DictReader(io.StringIO(file_content))
        for row in csv_reader:
            # Support multiple column names
            for col_name in ['hash', 'url', 'indicator', 'value', 'ioc']:
                if col_name in row and row[col_name].strip():
                    items.append(row[col_name].strip())
                    break
        
        if not items:
            raise ValueError("No valid hashes or URLs found in CSV")
        
        # Initialize session
        self.storage.bulk_sessions[session_id] = {
            'total': len(items),
            'processed': 0,
            'results': [],
            'status': 'processing',
            'started_at': datetime.now().isoformat()
        }
        
        lookup_tool = HashLookupTool()
        
        try:
            # Process in batches to avoid overwhelming APIs
            batch_size = 5
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                batch_results = []
                
                # Process batch concurrently
                tasks = []
                for item in batch:
                    if self._is_url(item):
                        tasks.append(self._lookup_url(lookup_tool, item))
                    elif _is_valid_hash(item):
                        tasks.append(lookup_tool.lookup_hash(item))
                    else:
                        # Skip invalid items
                        continue
                
                if tasks:
                    batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for j, item in enumerate(batch):
                    if j < len(batch_results):
                        result = batch_results[j]
                        if isinstance(result, Exception):
                            result = {'error': str(result)}
                        
                        threat_score = ThreatAnalyzer.calculate_threat_score(result) if isinstance(result, dict) else 0
                        summary = ThreatAnalyzer.generate_summary(result) if isinstance(result, dict) else "Error"
                        
                        item_result = {
                            'item': item,
                            'type': 'url' if self._is_url(item) else 'hash',
                            'threat_score': threat_score,
                            'summary': summary,
                            'details': result,
                            'timestamp': datetime.now().isoformat()
                        }
                        
                        results.append(item_result)
                        self.storage.bulk_sessions[session_id]['results'].append(item_result)
                
                # Update progress
                self.storage.bulk_sessions[session_id]['processed'] = len(results)
                
                # Small delay between batches to be nice to APIs
                await asyncio.sleep(1)
        
        finally:
            # Close API sessions
            for api in lookup_tool.apis.values():
                await api.close_session()
        
        # Mark session as completed
        self.storage.bulk_sessions[session_id]['status'] = 'completed'
        self.storage.bulk_sessions[session_id]['completed_at'] = datetime.now().isoformat()
        
        return {
            'session_id': session_id,
            'total_processed': len(results),
            'results': results,
            'summary': self._generate_bulk_summary(results)
        }
    
    def _is_url(self, item: str) -> bool:
        """Check if item is a URL."""
        try:
            result = urlparse(item)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    async def _lookup_url(self, lookup_tool: HashLookupTool, url: str) -> Dict[str, Any]:
        """Lookup URL using available APIs."""
        # For now, return a placeholder since URL lookup is complex
        # You can implement this later with the URL extension
        return {
            'not_found': True,
            'message': 'URL lookup not yet implemented'
        }
    
    def _generate_bulk_summary(self, results: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics for bulk analysis."""
        total = len(results)
        malicious_count = len([r for r in results if r['threat_score'] >= 50])
        clean_count = len([r for r in results if r['threat_score'] < 20])
        suspicious_count = total - malicious_count - clean_count
        
        return {
            'total_analyzed': total,
            'malicious': malicious_count,
            'suspicious': suspicious_count,
            'clean': clean_count,
            'threat_percentage': round((malicious_count / total) * 100, 1) if total > 0 else 0
        }
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get status of bulk processing session."""
        if session_id not in self.storage.bulk_sessions:
            return {'error': 'Session not found'}
        
        session = self.storage.bulk_sessions[session_id]
        progress_percentage = round((session['processed'] / session['total']) * 100, 1) if session['total'] > 0 else 0
        
        return {
            'session_id': session_id,
            'total': session['total'],
            'processed': session['processed'],
            'progress_percentage': progress_percentage,
            'completed': session['status'] == 'completed',
            'results_available': len(session.get('results', []))
        }

class APIHealthChecker:
    """Monitor API health and quotas."""
    
    def __init__(self, storage: InMemoryStorage):
        self.storage = storage
        self.cache_timeout = 300  # 5 minutes
    
    async def check_all_apis_health(self) -> Dict[str, Any]:
        """Check health of all configured APIs."""
        lookup_tool = HashLookupTool()
        health_results = {}
        
        try:
            for api_name, api_instance in lookup_tool.apis.items():
                if api_instance.is_configured():
                    health_results[api_name] = await self._check_api_health(api_name, api_instance)
                else:
                    health_results[api_name] = {
                        'status': 'not_configured',
                        'message': 'API key not configured',
                        'quota': None,
                        'response_time': None
                    }
        finally:
            for api in lookup_tool.apis.values():
                await api.close_session()
        
        # Cache results
        self.storage.api_health_cache = {
            'results': health_results,
            'timestamp': time.time()
        }
        
        return health_results
    
    async def _check_api_health(self, api_name: str, api_instance) -> Dict[str, Any]:
        """Check health of individual API."""
        start_time = time.time()
        
        try:
            # Try a simple test query with a known hash
            test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # SHA256 of empty string
            result = await api_instance.query_hash(test_hash)
            response_time = round((time.time() - start_time) * 1000, 2)  # ms
            
            # Determine status based on result
            if isinstance(result, dict) and result.get('error'):
                if 'rate limit' in result['error'].lower():
                    status = 'rate_limited'
                elif 'invalid' in result['error'].lower() or '401' in str(result['error']):
                    status = 'auth_error'
                else:
                    status = 'error'
                message = result['error']
            else:
                status = 'healthy'
                message = 'API responding normally'
            
            return {
                'status': status,
                'message': message,
                'response_time': response_time,
                'quota': {'remaining': 'Unknown', 'total': 'Unknown'}
            }
            
        except Exception as e:
            response_time = round((time.time() - start_time) * 1000, 2)
            return {
                'status': 'error',
                'message': str(e),
                'response_time': response_time,
                'quota': None
            }

# Initialize in-memory storage and managers
storage = InMemoryStorage()
bulk_processor = BulkProcessor(storage)
api_health_checker = APIHealthChecker(storage)

# FastAPI app
app = FastAPI()

try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except:
    pass

if getattr(sys, 'frozen', False):
    # If running as a PyInstaller EXE
    base_dir = sys._MEIPASS
else:
    # Normal Python interpreter
    base_dir = os.path.dirname(os.path.abspath(__file__))

templates = Jinja2Templates(directory=os.path.join(base_dir, "templates"))


@app.get("/", response_class=HTMLResponse)
async def get_form(request: Request):
    """Main page with enhanced features."""
    return templates.TemplateResponse("index.html", {
        "request": request, 
        "results": None, 
        "error": None,
        "history": storage.get_search_history(limit=10),
        "bookmarks": storage.get_bookmarks(),
        "show_dashboard": False
    })

@app.post("/lookup", response_class=HTMLResponse)
async def lookup_hash(request: Request, file_hash: str = Form(...)):
    """Single hash/URL lookup with enhanced features."""
    search_value = file_hash.strip().lower()
    search_type = 'url' if search_value.startswith('http') else 'hash'
    
    # Validate input
    if search_type == 'hash' and not _is_valid_hash(search_value):
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "results": None, 
            "error": "Invalid hash format!",
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": False
        })
    
    lookup_tool = HashLookupTool()
    
    try:
        # Perform lookup
        results = await lookup_tool.lookup_hash(search_value)
        
        # Calculate threat score and summary
        threat_score = ThreatAnalyzer.calculate_threat_score(results)
        summary = ThreatAnalyzer.generate_summary(results)
        
        # Add to search history
        storage.add_search_history(search_type, search_value, summary, threat_score)
        
        # Close API sessions
        for api in lookup_tool.apis.values():
            await api.close_session()
        
        return templates.TemplateResponse("index.html", {
            "request": request,
            "results": results,
            "error": None,
            "search_value": search_value,
            "search_type": search_type,
            "threat_score": threat_score,
            "threat_summary": summary,
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": True
        })
    
    except Exception as e:
        # Close sessions on error
        for api in lookup_tool.apis.values():
            await api.close_session()
        
        return templates.TemplateResponse("index.html", {
            "request": request,
            "results": None,
            "error": str(e),
            "history": storage.get_search_history(limit=10),
            "bookmarks": storage.get_bookmarks(),
            "show_dashboard": False
        })

@app.post("/bulk-upload")
async def bulk_upload(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Upload CSV for bulk processing."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")
    
    # Generate session ID
    session_id = str(uuid.uuid4())
    
    # Read file content
    content = await file.read()
    file_content = content.decode('utf-8')
    
    # Start background processing
    background_tasks.add_task(bulk_processor.process_csv, file_content, session_id)
    
    return {"session_id": session_id, "message": "Bulk processing started"}

@app.get("/bulk-status/{session_id}")
async def bulk_status(session_id: str):
    """Get bulk processing status."""
    return bulk_processor.get_session_status(session_id)

@app.get("/bulk-results/{session_id}")
async def bulk_results(session_id: str):
    """Get bulk processing results."""
    if session_id not in storage.bulk_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = storage.bulk_sessions[session_id]
    if session.get('status') != 'completed':
        raise HTTPException(status_code=202, detail="Processing not completed yet")
    
    return {
        'session_id': session_id,
        'results': session['results'],
        'summary': bulk_processor._generate_bulk_summary(session['results'])
    }

@app.post("/bookmark")
async def add_bookmark(search_type: str = Form(...), search_value: str = Form(...), title: str = Form(""), notes: str = Form("")):
    """Add bookmark."""
    success = storage.add_bookmark(search_type, search_value, title, notes)
    return {"success": success, "message": "Bookmarked successfully" if success else "Already bookmarked"}

@app.delete("/bookmark")
async def remove_bookmark(search_value: str):
    """Remove bookmark."""
    success = storage.remove_bookmark(search_value)
    return {"success": success}

@app.get("/api/health")
async def api_health():
    """Check API health status."""
    # Check if we have cached results
    if 'api_health_cache' in storage.__dict__ and storage.api_health_cache:
        cached_time = storage.api_health_cache.get('timestamp', 0)
        if time.time() - cached_time < 300:  # 5 minutes cache
            return storage.api_health_cache['results']
    
    # Get fresh health results
    health_results = await api_health_checker.check_all_apis_health()
    return health_results

@app.get("/api/history")
async def get_history():
    """Get search history."""
    return storage.get_search_history()

@app.get("/api/bookmarks")
async def get_bookmarks():
    """Get bookmarks."""
    return storage.get_bookmarks()

@app.get("/export/csv/{session_id}")
async def export_csv(session_id: str):
    """Export bulk results as CSV."""
    if session_id not in storage.bulk_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = storage.bulk_sessions[session_id]
    results = session.get('results', [])
    
    # Generate CSV content
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write headers
    writer.writerow(['Item', 'Type', 'Threat Score', 'Summary', 'Timestamp'])
    
    # Write data
    for result in results:
        writer.writerow([
            result['item'],
            result['type'],
            result['threat_score'],
            result['summary'].replace('\n', ' '),
            result['timestamp']
        ])
    
    csv_content = output.getvalue()
    output.close()
    
    return JSONResponse(
        content={"csv_data": csv_content, "filename": f"bulk_analysis_{session_id}.csv"},
        headers={"Content-Type": "application/json"}
    )

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)