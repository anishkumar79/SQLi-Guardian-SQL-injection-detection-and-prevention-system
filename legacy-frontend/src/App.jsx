import React, { useState, useEffect } from 'react';
import { Shield, Search, Database, AlertCircle, CheckCircle, Code, Server, Lock } from 'lucide-react';
import { analyzeQuery, getPreventionCode } from './utils/detector';
import './index.css';
import bannerImg from './assets/banner.png';

export default function App() {
  const [query, setQuery] = useState("");
  const [detections, setDetections] = useState([]);
  const [prevention, setPrevention] = useState("");
  const [isScanning, setIsScanning] = useState(false);

  useEffect(() => {
    if (query.length > 0) {
      setIsScanning(true);
      const timer = setTimeout(() => {
        const results = analyzeQuery(query);
        setDetections(results);
        setPrevention(getPreventionCode(query));
        setIsScanning(false);
      }, 300); // Simulate network latency/processing
      return () => clearTimeout(timer);
    } else {
      setDetections([]);
      setPrevention("");
    }
  }, [query]);

  return (
    <div className="app-container">
      <header className="header">
        <div className="hero-image-container">
          <img src={bannerImg} alt="SQL Security" className="hero-image" />
        </div>
        <h1>SQL Guardian</h1>
        <p>A next-generation system for detecting and preventing SQL injection attacks.</p>
        
        <div style={{display: 'flex', justifyContent: 'center', gap: '2rem', marginTop: '2rem'}}>
          <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)'}}>
            <Server size={16} className="accent-cyan" /> Secure Engine: Active
          </div>
          <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.9rem', color: 'var(--text-secondary)'}}>
            <Lock size={16} className="accent-cyan" /> Protection: Enabled
          </div>
        </div>
      </header>

      <div className="dashboard-grid">
        {/* Input Laboratory */}
        <section className="glass-card">
          <div className="card-title">
            <Search className="accent-cyan" size={24} />
            Input Laboratory
          </div>
          <p className="detection-message" style={{marginBottom: '1rem'}}>
            Simulate a SQL query to see how our detection engine handles it.
          </p>
          <textarea
            placeholder="Example: SELECT * FROM admin WHERE user = 'admin' AND pass = '' OR 1=1"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          <div style={{marginTop: '1rem', display: 'flex', flexWrap: 'wrap', gap: '0.5rem'}}>
            <span style={{fontSize: '0.75rem', color: 'var(--text-secondary)', alignSelf: 'center', marginRight: '0.5rem'}}>Quick Tests:</span>
            {[
              { label: "Bypass", code: "' OR 1=1 --" },
              { label: "Union", code: "UNION SELECT name, pass FROM users --" },
              { label: "Injection", code: "SELECT * FROM db; DROP TABLE sys; --" },
              { label: "Blind", code: "'; WAITFOR DELAY '0:0:5' --" }
            ].map((test, index) => (
              <button 
                key={index}
                onClick={() => setQuery(test.code)}
                style={{
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid var(--border)',
                  borderRadius: '20px',
                  padding: '4px 12px',
                  fontSize: '0.7rem',
                  color: 'var(--accent-cyan)',
                  cursor: 'pointer',
                  transition: '0.2s'
                }}
                onMouseOver={(e) => e.target.style.borderColor = 'var(--accent-cyan)'}
                onMouseOut={(e) => e.target.style.borderColor = 'var(--border)'}
              >
                {test.label}
              </button>
            ))}
          </div>
          
          <div style={{marginTop: '2.5rem'}}>
            <div className="card-title">
              <Code className="accent-cyan" size={24} />
              Prevention Strategy
            </div>
            <p className="detection-message" style={{marginBottom: '0.75rem'}}>
              The secure alternative using parameterized binding:
            </p>
            <div className="prevention-code">
              {prevention ? (
                <code>{prevention}</code>
              ) : (
                <span style={{opacity: 0.3, fontStyle: 'italic'}}>Parameterized query will appear here...</span>
              )}
            </div>
          </div>
        </section>

        {/* Intelligence Report */}
        <section className="glass-card">
          <div className="card-title">
            <Shield className={detections.length > 0 ? "pulse-red" : "accent-cyan"} size={24} />
            Intelligence Report {isScanning && <span className="scanning-dot">...</span>}
            {detections.length > 0 && (
              <span style={{fontSize: '0.75rem', background: 'var(--danger)', color: 'white', padding: '2px 10px', borderRadius: '20px', marginLeft: 'auto', fontWeight: 'bold'}}>
                DANGER DETECTED
              </span>
            )}
          </div>

          <div className="reports-container">
            {detections.length > 0 ? (
              detections.map((det, index) => (
                <div key={index} className="detection-item severity-high">
                  <div className="detection-title">
                    <span>{det.type}</span>
                    <AlertCircle size={18} />
                  </div>
                  <p className="detection-message">{det.message}</p>
                  <div className="suggestion">
                    <strong>Mitigation Strategy:</strong> {det.suggest}
                  </div>
                </div>
              ))
            ) : (
              <div className="no-detections">
                <CheckCircle size={64} style={{color: 'var(--success)', marginBottom: '1.5rem', opacity: 0.8}} />
                <h3>System Secure</h3>
                <p style={{marginTop: '0.5rem'}}>Enter a potentially malicious query to see our analysis engine in action.</p>
              </div>
            )}
          </div>
          
          {detections.length > 0 && (
            <div style={{marginTop: '1.5rem', padding: '1rem', border: '1px solid var(--danger)', borderRadius: '1rem', background: 'rgba(239, 68, 68, 0.05)'}}>
              <p style={{fontSize: '0.85rem', color: 'var(--danger)', fontStyle: 'italic'}}>
                * Warning: Direct execution of the input query on a production database could lead to a total system compromise.
              </p>
            </div>
          )}
        </section>
      </div>

      <div style={{marginTop: '4rem', padding: '2rem', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', opacity: 0.6, fontSize: '0.85rem'}}>
        <div>
          <Database size={20} style={{marginRight: '0.5rem', verticalAlign: 'middle'}} />
          EventStar Security Shield v2.4
        </div>
        <div>
          Advanced SQLi Detection Engine v1.0.2-stable
        </div>
      </div>
    </div>
  );
}
