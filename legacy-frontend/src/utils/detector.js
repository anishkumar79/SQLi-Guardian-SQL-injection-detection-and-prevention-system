export const analyzeQuery = (query) => {
  const detections = [];
  if (!query) return detections;

  // Tautology detection (OR 1=1, OR 'a'='a', OR true, etc.)
  const tautologyPatterns = [
    /\bOR\s+(['"]?\w+['"]?)\s*=\s*(['"]?\w+['"]?)/i,
    /\bOR\s+TRUE\b/i,
    /\bOR\s+1\s*=\s*1\b/i
  ];
  tautologyPatterns.forEach(pattern => {
    if (pattern.test(query)) {
      detections.push({
        type: 'Tautology (Bypass)',
        severity: 'Critical',
        message: 'Logic bypass detected. The attacker is trying to make a WHERE clause always true.',
        suggest: 'Never use string interpolation for SQL queries. Use Parameterized Queries (Prepared Statements).'
      });
    }
  });

  // Union-based detection
  if (/\bUNION\s+(ALL\s+)?SELECT\b/i.test(query)) {
    detections.push({
      type: 'Union-Based Injection',
      severity: 'Critical',
      message: 'Attempt to combine results from another table. This is used for data exfiltration.',
      suggest: 'Implement strict input validation and use a Web Application Firewall (WAF).'
    });
  }

  // Comment-based detection
  if (/(--|#|\/\*)/.test(query)) {
    detections.push({
      type: 'Comment Truncation',
      severity: 'Medium',
      message: 'SQL comments detected. Attackers use this to ignore the rest of your original query.',
      suggest: 'Sanitize special characters or use a library that handles escaping automatically.'
    });
  }

  // Stacked queries detection
  if (/;/.test(query) && /\b(DROP|UPDATE|DELETE|INSERT|ALTER)\b/i.test(query)) {
    detections.push({
      type: 'Stacked Queries',
      severity: 'Critical',
      message: 'Semi-colon detected following a query. This could execute malicious secondary commands.',
      suggest: 'Disable multi-statement support in your database driver.'
    });
  }

  // Blind SQLi / Time-based
  if (/\bWAITFOR\s+DELAY\b/i.test(query) || /\bSLEEP\(\d+\)/i.test(query)) {
    detections.push({
      type: 'Time-Based Blind SQLi',
      severity: 'Critical',
      message: 'Database delay function detected. Used to exfiltrate data bit-by-bit via timing.',
      suggest: 'Set database timeout limits and monitor for slow, repetitive queries.'
    });
  }

  // Dangerous Admin keywords
  const keywords = ['XP_CMDSHELL', 'OPENROWSET', 'SHUTDOWN'];
  keywords.forEach(keyword => {
    if (new RegExp(`\\b${keyword}\\b`, 'i').test(query)) {
      detections.push({
        type: 'Admin Command Injection',
        severity: 'Critical',
        message: `Dangerous administrative command detected: ${keyword}.`,
        suggest: 'Use a low-privilege database user that cannot execute system commands.'
      });
    }
  });

  return detections;
}

export const getPreventionCode = (query) => {
  if (!query) return '';
  
  // This is a simplified "parameterizer" for demonstration
  // Real world uses placeholders in the driver
  let fixed = query;
  
  // Replace string content with placeholders
  fixed = fixed.replace(/'[^']*'/g, '?');
  fixed = fixed.replace(/"[^"]*"/g, '?');

  // Replace numbers with placeholders
  fixed = fixed.replace(/\b\d+\b/g, '?');

  return fixed;
}
