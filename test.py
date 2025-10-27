"""
NeuraShield Solutions API
Flask backend for code analysis - Updated for Real NeuraShield Integration
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sys
import json
import uuid
import re
from datetime import datetime
from pathlib import Path
import tempfile
import threading

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import NeuraShield modules
try:
    from phase_1.code_extractor import GitHubCodeExtractor
    from phase_1.vector_store import ChromaVectorStore
    from phase_1.embedding_generator import EmbeddingGenerator
    from phase_2.rag_analyzer import RAGAnalyzer
    NEURASHIELD_AVAILABLE = True
except ImportError:
    NEURASHIELD_AVAILABLE = False
    print("Warning: NeuraShield modules not found. Running in demo mode.")

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration - Store outside webdev folder
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
TEMP_FOLDER = os.path.join(PROJECT_ROOT, '.temp_data')
os.makedirs(TEMP_FOLDER, exist_ok=True)

# Keep reports in memory only, with expiration
report_cache = {}
REPORT_CACHE_TIMEOUT = 3600  # 1 hour in seconds


# In-memory job storage
jobs = {}

# Initialize NeuraShield components if available
if NEURASHIELD_AVAILABLE:
    try:
        vector_store = ChromaVectorStore(
            collection_name="neurashield_code_v1",
            persist_directory="phase_1/chroma_db"
        )
        embedding_gen = EmbeddingGenerator()
        analyzer = RAGAnalyzer(
            vector_store=vector_store,
            embedding_generator=embedding_gen,
            llm_model="gpt-4o",
            top_k=5
        )
    except Exception as e:
        print(f"Error initializing NeuraShield: {e}")
        NEURASHIELD_AVAILABLE = False


def create_job(job_type, input_data):
    """Create a new analysis job"""
    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        'id': job_id,
        'type': job_type,
        'status': 'pending',
        'created_at': datetime.now().isoformat(),
        'input': input_data,
        'result': None,
        'error': None
    }
    return job_id


def update_job(job_id, status, result=None, error=None):
    """Update job status"""
    if job_id in jobs:
        jobs[job_id]['status'] = status
        jobs[job_id]['updated_at'] = datetime.now().isoformat()
        if result:
            jobs[job_id]['result'] = result
        if error:
            jobs[job_id]['error'] = error

def cleanup_expired_reports():
    """Remove expired reports from cache"""
    current_time = datetime.now().timestamp()
    expired_jobs = [
        job_id for job_id, report in report_cache.items()
        if current_time - report['timestamp'] > REPORT_CACHE_TIMEOUT
    ]
    for job_id in expired_jobs:
        del report_cache[job_id]
        if job_id in jobs:
            del jobs[job_id]

def parse_neurashield_report(report_text):
    """Parse actual NeuraShield report text into structured JSON"""
    try:
        # Initialize result structure
        result = {
            'timestamp': datetime.now().isoformat(),
            'raw_report': report_text,
            'security_analysis': {
                'overall_security_score': 0,
                'overall_severity': 'Unknown',
                'vulnerabilities': [],
                'risk_summary': '',
                'immediate_actions': []
            },
            'bug_analysis': {
                'has_bugs': False,
                'bugs_found': [],
                'overall_risk': 'low'
            },
            'optimization_analysis': {
                'current_complexity': {
                    'time': 'O(1)',
                    'space': 'O(1)',
                    'bottlenecks': []
                },
                'optimizations': [],
                'estimated_speedup': 'N/A'
            },
            'code_quality': {
                'score': 70,
                'grade': 'C',
                'issues': 0
            }
        }
        
        # Parse Security Section
        security_match = re.search(r'Overall Security Score:\s*([0-9.]+)/10', report_text)
        if security_match:
            result['security_analysis']['overall_security_score'] = float(security_match.group(1))
        
        severity_match = re.search(r'Severity:\s*(\w+)', report_text)
        if severity_match:
            result['security_analysis']['overall_severity'] = severity_match.group(1)
        
        # Parse vulnerabilities
        vuln_count_match = re.search(r'🛡️\s*VULNERABILITIES:\s*(\d+)', report_text)
        if vuln_count_match and int(vuln_count_match.group(1)) > 0:
            # Extract vulnerability details
            vuln_sections = re.split(r'\n\d+\.\s+', report_text)
            for section in vuln_sections[1:]:  # Skip first split
                lines = section.strip().split('\n')
                if len(lines) >= 4:
                    vuln_name = lines[0].strip()
                    cvss_score = 0
                    cvss_vector = ''
                    cwe_id = ''
                    remediation = ''
                    
                    for line in lines[1:]:
                        line = line.strip()
                        if line.startswith('CVSS Score:'):
                            try:
                                cvss_score = float(line.split(':', 1)[1].strip())
                            except:
                                cvss_score = 0
                        elif line.startswith('CVSS Vector:'):
                            cvss_vector = line.split(':', 1)[1].strip()
                        elif line.startswith('CWE:'):
                            cwe_id = line.split(':', 1)[1].strip()
                        elif line.startswith('Remediation:'):
                            remediation = line.split(':', 1)[1].strip()
                    
                    if vuln_name:
                        result['security_analysis']['vulnerabilities'].append({
                            'type': vuln_name,
                            'cvss_score': cvss_score,
                            'cvss_vector': cvss_vector,
                            'cwe_id': cwe_id,
                            'remediation': remediation,
                            'line': 'general'
                        })
        
        # Parse Bug Section
        bugs_match = re.search(r'⚠️\s*BUGS FOUND:\s*(\d+)', report_text)
        if bugs_match:
            bug_count = int(bugs_match.group(1))
            result['bug_analysis']['has_bugs'] = bug_count > 0
            
            if bug_count > 0:
                # Parse overall risk
                risk_match = re.search(r'Overall Risk:\s*(\w+)', report_text)
                if risk_match:
                    result['bug_analysis']['overall_risk'] = risk_match.group(1).lower()
                
                # Parse individual bugs
                bug_sections = re.split(r'\n\d+\.\s+', report_text)
                for section in bug_sections[1:]:
                    lines = section.strip().split('\n')
                    if len(lines) >= 2:
                        # Parse bug header
                        header = lines[0].strip()
                        severity_match = re.search(r'\(Severity:\s*(\w+)\)', header)
                        bug_name = re.sub(r'\s*\(Severity:.*?\)', '', header).strip()
                        severity = severity_match.group(1).lower() if severity_match else 'medium'
                        
                        line_num = 'general'
                        description = ''
                        fix = ''
                        
                        for line in lines[1:]:
                            line = line.strip()
                            if line.startswith('Line:'):
                                line_num = line.split(':', 1)[1].strip()
                            elif line.startswith('Description:'):
                                description = line.split(':', 1)[1].strip()
                            elif line.startswith('Fix:'):
                                fix = line.split(':', 1)[1].strip()
                        
                        if bug_name:
                            result['bug_analysis']['bugs_found'].append({
                                'type': bug_name,
                                'severity': severity,
                                'line': line_num,
                                'description': description,
                                'fix': fix,
                                'impact': {
                                    'confidentiality': 'Low',
                                    'integrity': 'Low', 
                                    'availability': 'Low'
                                },
                                'cwe_id': 'CWE-200'
                            })
        
        # Parse Optimization Section
        if '⚡ OPTIMIZATIONS FOUND:' in report_text:
            opt_match = re.search(r'⚡ OPTIMIZATIONS FOUND:\s*(\d+)', report_text)
            if opt_match:
                opt_count = int(opt_match.group(1))
                result['optimization_analysis']['optimizations'] = [
                    {
                        'type': 'Performance',
                        'description': f'{opt_count} optimization opportunities identified',
                        'improvement': f'{opt_count} suggestion(s)',
                        'trade_offs': 'See full report for details'
                    }
                ]
                
                # Parse estimated speedup
                speedup_match = re.search(r'Estimated Speedup:\s*([^\n]+)', report_text)
                if speedup_match:
                    result['optimization_analysis']['estimated_speedup'] = speedup_match.group(1).strip()
        
        # Parse complexity
        time_match = re.search(r'Time:\s*([^\n]+)', report_text)
        if time_match:
            result['optimization_analysis']['current_complexity']['time'] = time_match.group(1).strip()
        
        space_match = re.search(r'Space:\s*([^\n]+)', report_text)
        if space_match:
            result['optimization_analysis']['current_complexity']['space'] = space_match.group(1).strip()
        
        # Parse bottlenecks
        bottlenecks_match = re.search(r'Bottlenecks:\s*([^\n]+)', report_text)
        if bottlenecks_match:
            bottlenecks = [b.strip() for b in bottlenecks_match.group(1).split(',')]
            result['optimization_analysis']['current_complexity']['bottlenecks'] = bottlenecks
        
        # Parse risk summary
        risk_summary_match = re.search(r'Risk Summary:\s*\n\s*([^\n]+(?:\n\s*[^\n]+)*)', report_text)
        if risk_summary_match:
            result['security_analysis']['risk_summary'] = risk_summary_match.group(1).strip()
        
        # Parse immediate actions
        actions_section = re.search(r'Immediate Actions Required:\s*\n((?:\s*•[^\n]+\n?)+)', report_text)
        if actions_section:
            actions = re.findall(r'•\s*([^\n]+)', actions_section.group(1))
            result['security_analysis']['immediate_actions'] = actions
        
        # Calculate code quality score
        security_score = result['security_analysis']['overall_security_score']
        bug_count = len(result['bug_analysis']['bugs_found'])
        vuln_count = len(result['security_analysis']['vulnerabilities'])
        
        # Lower security score = higher quality (inverse relationship)
        quality_score = max(10, 100 - (security_score * 5) - (bug_count * 15) - (vuln_count * 10))
        result['code_quality']['score'] = int(quality_score)
        
        # Assign grade
        if quality_score >= 90:
            result['code_quality']['grade'] = 'A'
        elif quality_score >= 80:
            result['code_quality']['grade'] = 'B'
        elif quality_score >= 70:
            result['code_quality']['grade'] = 'C'
        elif quality_score >= 60:
            result['code_quality']['grade'] = 'D'
        else:
            result['code_quality']['grade'] = 'F'
            
        result['code_quality']['issues'] = vuln_count + bug_count
        
        return result
        
    except Exception as e:
        print(f"Error parsing NeuraShield report: {e}")
        return generate_mock_analysis("Error parsing report")


def run_analysis(job_id, code, analysis_type='all'):
    """Run code analysis in background thread"""
    try:
        if NEURASHIELD_AVAILABLE and os.getenv('OPENAI_API_KEY'):
            # Real analysis using NeuraShield
            update_job(job_id, 'processing')
            
            # Use your actual NeuraShield analyzer
            raw_results = analyzer.analyze_code(code=code, analysis_type=analysis_type)
            
            # Generate the text report
            report_text = analyzer.generate_report(raw_results)
            
            # Parse the report text into structured JSON for frontend
            parsed_results = parse_neurashield_report(report_text)
            
            update_job(job_id, 'completed', result=parsed_results)
            
            # Store report in memory cache with timestamp (NOT on disk)
            report_cache[job_id] = {
                'content': report_text,
                'timestamp': datetime.now().timestamp()
            }
        else:
            # Demo mode with realistic mock data
            import time
            update_job(job_id, 'processing')
            time.sleep(3)  # Simulate processing time
            
            mock_result = generate_mock_analysis(code)
            update_job(job_id, 'completed', result=mock_result)
            
            # Store mock report in memory cache
            report_text = generate_mock_report_text(mock_result)
            report_cache[job_id] = {
                'content': report_text,
                'timestamp': datetime.now().timestamp()
            }
                
    except Exception as e:
        update_job(job_id, 'failed', error=str(e))


def generate_mock_analysis(code):
    """Generate mock analysis results matching your format"""
    has_sql = 'select' in code.lower() or 'insert' in code.lower() or 'database' in code.lower()
    has_loop = 'for ' in code or 'while ' in code
    has_flask = 'app.run' in code or 'Flask' in code or 'flask' in code.lower()
    
    # Determine security score based on code content
    if has_flask:
        security_score = 9.8
        severity = 'CRITICAL'
        vulnerabilities = [
            {
                'type': 'Insecure Default Configuration',
                'cvss_score': 9.8,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'cwe_id': 'CWE-200',
                'remediation': 'Use a production-ready server like Gunicorn or uWSGI',
                'line': 'general'
            }
        ]
    elif has_sql:
        security_score = 7.5
        severity = 'HIGH'
        vulnerabilities = [
            {
                'type': 'SQL Injection',
                'cvss_score': 8.5,
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
                'cwe_id': 'CWE-89',
                'remediation': 'Use parameterized queries or prepared statements',
                'line': '5'
            }
        ]
    else:
        security_score = 3.2
        severity = 'LOW'
        vulnerabilities = []
    
    bugs = []
    if has_loop:
        bugs.append({
            'type': 'Performance Issue',
            'severity': 'medium',
            'line': '8',
            'description': 'Inefficient loop iteration pattern detected',
            'fix': 'Use list comprehension or vectorized operations for better performance',
            'impact': {
                'confidentiality': 'None',
                'integrity': 'None',
                'availability': 'Low'
            },
            'cwe_id': 'CWE-407'
        })
    
    optimizations = []
    if has_loop:
        optimizations.append({
            'type': 'Performance',
            'description': 'Replace explicit loop with list comprehension',
            'improvement': '2-3x faster execution',
            'trade_offs': 'None significant'
        })
    
    return {
        'timestamp': datetime.now().isoformat(),
        'type': 'demo',
        'security_analysis': {
            'overall_security_score': security_score,
            'overall_severity': severity,
            'vulnerabilities': vulnerabilities,
            'risk_summary': f'{severity.title()} risk detected. ' + ('Immediate action required.' if vulnerabilities else 'No major security issues found.'),
            'immediate_actions': ['Fix identified vulnerabilities', 'Review security configurations'] if vulnerabilities else []
        },
        'bug_analysis': {
            'has_bugs': len(bugs) > 0,
            'bugs_found': bugs,
            'overall_risk': 'medium' if bugs else 'low'
        },
        'optimization_analysis': {
            'current_complexity': {
                'time': 'O(n)' if has_loop else 'O(1)',
                'space': 'O(n)',
                'bottlenecks': ['Loop iteration'] if has_loop else []
            },
            'optimizations': optimizations,
            'estimated_speedup': '2-3x' if optimizations else 'N/A'
        },
        'code_quality': {
            'score': max(20, 100 - (security_score * 5) - (len(bugs) * 15) - (len(vulnerabilities) * 10)),
            'grade': 'C',
            'issues': len(vulnerabilities) + len(bugs)
        }
    }


def generate_mock_report_text(analysis):
    """Generate mock text report matching your format"""
    timestamp = analysis['timestamp']
    bugs = analysis['bug_analysis']['bugs_found']
    vulns = analysis['security_analysis']['vulnerabilities']
    opts = analysis['optimization_analysis']['optimizations']
    
    return f"""======================================================================
NEURASHIELD.AI - CODE ANALYSIS REPORT
======================================================================
Timestamp: {timestamp}
Analysis Type: all
Retrieved Patterns: 5
Code Length: {len(str(analysis))} characters

----------------------------------------------------------------------

## BUG DETECTION
----------------------------------------------------------------------
{'⚠️  BUGS FOUND: ' + str(len(bugs)) if bugs else '✓ No bugs detected'}
{f"Overall Risk: {analysis['bug_analysis']['overall_risk'].upper()}" if bugs else ""}

{chr(10).join([f"{i+1}. {bug['type']} (Severity: {bug['severity'].upper()})" + chr(10) + 
               f"   Line: {bug['line']}" + chr(10) + 
               f"   Description: {bug['description']}" + chr(10) + 
               f"   Fix: {bug['fix']}" + chr(10) +
               f"   CWE: {bug.get('cwe_id', 'N/A')}"
               for i, bug in enumerate(bugs)]) if bugs else ""}

## CODE OPTIMIZATION
----------------------------------------------------------------------
Current Complexity:
  Time: {analysis['optimization_analysis']['current_complexity']['time']}
  Space: {analysis['optimization_analysis']['current_complexity']['space']}
{"  Bottlenecks: " + ", ".join(analysis['optimization_analysis']['current_complexity']['bottlenecks']) if analysis['optimization_analysis']['current_complexity']['bottlenecks'] else ""}

{f"⚡ OPTIMIZATIONS FOUND: {len(opts)}" if opts else "✓ Code is well-optimized"}
{f"Estimated Speedup: {analysis['optimization_analysis']['estimated_speedup']}" if opts else ""}

{chr(10).join([f"{i+1}. {opt['type'].upper()}: {opt['description']}" + chr(10) +
               f"   Improvement: {opt['improvement']}" + chr(10) +
               f"   Trade-offs: {opt['trade_offs']}"
               for i, opt in enumerate(opts)]) if opts else ""}

## SECURITY SCORING (CVSS v3.1)
----------------------------------------------------------------------
Overall Security Score: {analysis['security_analysis']['overall_security_score']}/10
Severity: {analysis['security_analysis']['overall_severity']}

Risk Summary:
  {analysis['security_analysis']['risk_summary']}

🛡️  VULNERABILITIES: {len(vulns)}

{chr(10).join([f"{i+1}. {vuln['type']}" + chr(10) + 
               f"   CVSS Score: {vuln['cvss_score']}" + chr(10) + 
               f"   CVSS Vector: {vuln['cvss_vector']}" + chr(10) + 
               f"   CWE: {vuln['cwe_id']}" + chr(10) + 
               f"   Remediation: {vuln['remediation']}" 
               for i, vuln in enumerate(vulns)]) if vulns else ""}

{f"Immediate Actions Required:" + chr(10) + chr(10).join([f"  • {action}" for action in analysis['security_analysis']['immediate_actions']]) if analysis['security_analysis']['immediate_actions'] else ""}

======================================================================
END OF REPORT
======================================================================
"""


# All existing Flask routes remain the same
@app.route('/')
def index():
    """API root"""
    cleanup_expired_reports()  # Clean up old reports
    return jsonify({
        'message': 'NeuraShield Solutions API',
        'version': '1.0.0',
        'status': 'running',
        'neurashield_enabled': NEURASHIELD_AVAILABLE
    })


@app.route('/api/analyze/github', methods=['POST'])
def analyze_github():
    """Analyze GitHub repository"""
    data = request.get_json()
    repo_url = data.get('repo_url')
    
    if not repo_url:
        return jsonify({'error': 'Repository URL is required'}), 400
    
    job_id = create_job('github', {'repo_url': repo_url})
    
    def process_repo():
        try:
            if NEURASHIELD_AVAILABLE:
                extractor = GitHubCodeExtractor(repo_url)
                code_files = extractor.extract_python_files()
                combined_code = '\n\n'.join([f['source_code'] for f in code_files[:5]])
                extractor.cleanup()
                run_analysis(job_id, combined_code)
            else:
                run_analysis(job_id, "# Sample GitHub repository code\ndef main():\n    pass")
        except Exception as e:
            update_job(job_id, 'failed', error=str(e))
    
    thread = threading.Thread(target=process_repo)
    thread.start()
    
    return jsonify({
        'job_id': job_id,
        'status': 'pending',
        'message': 'Analysis started'
    })


@app.route('/api/analyze/code', methods=['POST'])
def analyze_code():
    """Analyze pasted code"""
    data = request.get_json()
    code = data.get('code')
    
    if not code:
        return jsonify({'error': 'Code is required'}), 400
    
    job_id = create_job('code', {'code': code})
    thread = threading.Thread(target=run_analysis, args=(job_id, code))
    thread.start()
    
    return jsonify({
        'job_id': job_id,
        'status': 'pending',
        'message': 'Analysis started'
    })


@app.route('/api/analyze/file', methods=['POST'])
def analyze_file():
    """Analyze uploaded file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Read file content directly without saving
    try:
        code = file.read().decode('utf-8')
    except Exception as e:
        return jsonify({'error': f'Failed to read file: {str(e)}'}), 400
    
    # Create job
    job_id = create_job('file', {'filename': file.filename})
    
    # Start analysis in background
    thread = threading.Thread(target=run_analysis, args=(job_id, code))
    thread.start()
    
    return jsonify({
        'job_id': job_id,
        'status': 'pending',
        'message': 'Analysis started'
    })


@app.route('/api/status/<job_id>', methods=['GET'])
def get_status(job_id):
    """Get analysis status"""
    if job_id not in jobs:
        return jsonify({'error': 'Job not found'}), 404
    
    job = jobs[job_id]
    response = {
        'job_id': job_id,
        'status': job['status'],
        'created_at': job['created_at']
    }
    
    if job['status'] == 'completed':
        response['analysis'] = job['result']
    elif job['status'] == 'failed':
        response['error'] = job['error']
    
    return jsonify(response)

@app.route('/api/download/<job_id>/<format>', methods=['GET'])
def download_report(job_id, format):
    """Download analysis report from memory"""
    if job_id not in jobs:
        return jsonify({'error': 'Job not found'}), 404
    
    job = jobs[job_id]
    
    if job['status'] != 'completed':
        return jsonify({'error': 'Analysis not completed'}), 400
    
    # Check if report exists in cache
    if job_id not in report_cache:
        return jsonify({'error': 'Report expired or not found'}), 404
    
    # Check if report has expired (older than 1 hour)
    report_data = report_cache[job_id]
    if datetime.now().timestamp() - report_data['timestamp'] > REPORT_CACHE_TIMEOUT:
        # Clean up expired report
        del report_cache[job_id]
        return jsonify({'error': 'Report has expired. Please re-run analysis.'}), 404
    
    content = report_data['content']
    
    if format == 'txt':
        # Generate text file in memory
        from io import BytesIO
        buffer = BytesIO()
        buffer.write(content.encode('utf-8'))
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name='neurashield-report.txt', mimetype='text/plain')
        
    elif format == 'html':
        # Convert to HTML in memory
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>NeuraShield Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; padding: 2rem; background: #f5f5f5; }}
        .container {{ max-width: 900px; margin: 0 auto; background: white; padding: 2rem; }}
        pre {{ background: #f8f9fa; padding: 1rem; border-radius: 4px; overflow-x: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <pre>{content}</pre>
    </div>
</body>
</html>
        """
        
        from io import BytesIO
        buffer = BytesIO()
        buffer.write(html_content.encode('utf-8'))
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name='neurashield-report.html', mimetype='text/html')
        
    elif format == 'pdf':
        # Generate PDF using reportlab
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Preformatted
            from reportlab.lib.units import inch
            from io import BytesIO
            
            buffer = BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            story = []
            
            # Use preformatted text to preserve formatting
            styles = getSampleStyleSheet()
            for line in content.split('\n'):
                para = Preformatted(line, styles['Code'])
                story.append(para)
            
            doc.build(story)
            buffer.seek(0)
            return send_file(buffer, as_attachment=True, download_name='neurashield-report.pdf', mimetype='application/pdf')
        except ImportError:
            return jsonify({'error': 'PDF generation requires reportlab. Install with: pip install reportlab'}), 501
        except Exception as e:
            return jsonify({'error': f'PDF generation failed: {str(e)}'}), 500
    else:
        return jsonify({'error': 'Invalid format'}), 400


if __name__ == '__main__':
    print("""
    ╔═══════════════════════════════════════╗
    ║   NeuraShield Solutions API Server   ║
    ╚═══════════════════════════════════════╝
    
    Server running at: http://localhost:5050
    NeuraShield Mode: {'ENABLED' if NEURASHIELD_AVAILABLE else 'DEMO MODE'}
    
    Endpoints:
    - POST /api/analyze/github
          
    - POST /api/analyze/code
    - POST /api/analyze/file
    - GET  /api/status/<job_id>
    - GET  /api/download/<job_id>/<format>
    """)
    
    app.run(debug=True, host='0.0.0.0', port=5050)
