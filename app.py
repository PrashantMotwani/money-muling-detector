from flask import Flask, request, jsonify, render_template, send_file
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pandas as pd
import networkx as nx
import json
import io

app = Flask(__name__)
CORS(app)

# Simple SQLite Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///money_muling.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ==================== DATABASE MODELS ====================

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200))
    upload_time = db.Column(db.DateTime, default=datetime.utcnow)
    total_transactions = db.Column(db.Integer)
    suspicious_count = db.Column(db.Integer)
    rings_count = db.Column(db.Integer)

class SuspiciousAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.String(100))
    score = db.Column(db.Float)
    patterns = db.Column(db.String(500))
    upload_id = db.Column(db.Integer, db.ForeignKey('upload.id'))

# ==================== DETECTOR ====================

class Detector:
    def __init__(self):
        self.G = nx.DiGraph()
        
    def analyze(self, df):
        # Build graph
        for _, row in df.iterrows():
            sender = row['sender_id']
            receiver = row['receiver_id']
            amount = row['amount']
            
            if not self.G.has_edge(sender, receiver):
                self.G.add_edge(sender, receiver, weight=amount, count=1)
            else:
                self.G[sender][receiver]['weight'] += amount
                self.G[sender][receiver]['count'] += 1
        
        # Find cycles
        cycles = []
        try:
            all_cycles = list(nx.simple_cycles(self.G))
            cycles = [c for c in all_cycles if 3 <= len(c) <= 5]
        except:
            pass
        
        # Find high-degree nodes (fan patterns)
        fan_nodes = [n for n in self.G.nodes() if self.G.degree(n) >= 10]
        
        # Calculate scores
        scores = {}
        for node in self.G.nodes():
            score = 0
            patterns = []
            
            if any(node in c for c in cycles):
                score += 50
                patterns.append('cycle')
            
            if node in fan_nodes:
                score += 40
                patterns.append('high_velocity')
            
            if self.G.degree(node) > 5:
                score += 20
                patterns.append('suspicious_activity')
            
            scores[node] = {'score': min(score, 100), 'patterns': patterns}
        
        # Build rings
        rings = []
        ring_id = 1
        for cycle in cycles:
            rings.append({
                'ring_id': f'RING_{ring_id:03d}',
                'members': cycle,
                'type': 'cycle',
                'risk': 75.0
            })
            ring_id += 1
        
        # Get suspicious accounts
        suspicious = []
        for acc, data in sorted(scores.items(), key=lambda x: x[1]['score'], reverse=True):
            if data['score'] > 30:
                ring = None
                for r in rings:
                    if acc in r['members']:
                        ring = r['ring_id']
                        break
                
                suspicious.append({
                    'account_id': acc,
                    'suspicion_score': data['score'],
                    'detected_patterns': data['patterns'],
                    'ring_id': ring
                })
        
        return {
            'suspicious_accounts': suspicious,
            'fraud_rings': rings,
            'graph': self.get_graph_data(suspicious, rings),
            'summary': {
                'total_accounts_analyzed': self.G.number_of_nodes(),
                'suspicious_accounts_flagged': len(suspicious),
                'fraud_rings_detected': len(rings)
            }
        }
    
    def get_graph_data(self, suspicious, rings):
        suspicious_ids = {s['account_id'] for s in suspicious}
        ring_members = set()
        for r in rings:
            ring_members.update(r['members'])
        
        nodes = []
        for node in self.G.nodes():
            nodes.append({
                'id': node,
                'label': node,
                'suspicious': node in suspicious_ids,
                'in_ring': node in ring_members,
                'degree': self.G.degree(node)
            })
        
        edges = []
        for u, v, data in self.G.edges(data=True):
            edges.append({
                'from': u,
                'to': v,
                'weight': data['weight'],
                'count': data['count']
            })
        
        return {'nodes': nodes, 'edges': edges}

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    try:
        file = request.files['file']
        df = pd.read_csv(file)
        
        # Analyze
        detector = Detector()
        result = detector.analyze(df)
        
        # Save to database
        upload = Upload(
            filename=file.filename,
            total_transactions=len(df),
            suspicious_count=len(result['suspicious_accounts']),
            rings_count=len(result['fraud_rings'])
        )
        db.session.add(upload)
        db.session.commit()
        
        # Save suspicious accounts
        for acc in result['suspicious_accounts']:
            susp = SuspiciousAccount(
                account_id=acc['account_id'],
                score=acc['suspicion_score'],
                patterns=','.join(acc['detected_patterns']),
                upload_id=upload.id
            )
            db.session.add(susp)
        
        db.session.commit()
        
        return jsonify({'success': True, 'analysis': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def history():
    uploads = Upload.query.order_by(Upload.upload_time.desc()).limit(10).all()
    return jsonify({
        'batches': [{
            'id': u.id,
            'filename': u.filename,
            'upload_time': u.upload_time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_transactions': u.total_transactions,
            'suspicious_count': u.suspicious_count,
            'rings_count': u.rings_count
        } for u in uploads]
    })

@app.route('/api/stats')
def stats():
    total_uploads = Upload.query.count()
    total_suspicious = SuspiciousAccount.query.count()
    
    return jsonify({
        'total_batches': total_uploads,
        'total_suspicious_accounts': total_suspicious,
        'total_fraud_rings': db.session.query(db.func.sum(Upload.rings_count)).scalar() or 0
    })

@app.route('/download-json')
def download():
    # Get latest analysis
    latest = Upload.query.order_by(Upload.upload_time.desc()).first()
    if not latest:
        return jsonify({'error': 'No data'}), 404
    
    accounts = SuspiciousAccount.query.filter_by(upload_id=latest.id).all()
    
    output = {
        'suspicious_accounts': [{
            'account_id': a.account_id,
            'suspicion_score': a.score,
            'detected_patterns': a.patterns.split(',') if a.patterns else []
        } for a in accounts]
    }
    
    json_str = json.dumps(output, indent=2)
    return send_file(
        io.BytesIO(json_str.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name='results.json'
    )

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database ready!")
    app.run(debug=True, host='0.0.0.0', port=5000)