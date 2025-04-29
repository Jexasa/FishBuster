// heuristics.js
// Heuristic checks for phishing detection
window.checkPhishingHeuristics = async function(sender, content, links, domain) {
  let score = 0;
  const warnings = [];

  // Optimize by limiting checks and using async where possible
  const checks = [
    async () => {
      // Urgency keywords
      const urgencyKeywords = ['urgent', 'act now', 'immediate', 'deadline', 'last chance'];
      const hasUrgency = urgencyKeywords.some(keyword => content.includes(keyword));
      if (hasUrgency) {
        score += 15;
        warnings.push('Contains urgency keywords that may indicate phishing.');
      }
    },
    async () => {
      // Suspicious sender domain
      const senderDomain = sender.split('@')[1] || '';
      const commonDomains = ['gmail.com', 'yahoo.com', 'outlook.com', 'aol.com', 'proton.me'];
      if (!commonDomains.includes(senderDomain) && !senderDomain.includes(domain)) {
        score += 10;
        warnings.push('Sender domain is unfamiliar or mismatched with email service.');
      }
    },
    async () => {
      // Suspicious links
      if (links.length > 0) {
        const hasHttp = links.some(link => link.startsWith('http://'));
        if (hasHttp) {
          score += 20;
          warnings.push('Contains HTTP links (not secure HTTPS), potential phishing risk.');
        }
        const hasMismatch = links.some(link => !link.includes(domain));
        if (hasMismatch) {
          score += 15;
          warnings.push('Links do not match the email domain, possible phishing attempt.');
        }
      }
    }
  ];

  // Run checks in parallel to improve performance
  await Promise.all(checks.map(check => check()));

  return { score, warnings };
};