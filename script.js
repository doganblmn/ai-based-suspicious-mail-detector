const form = document.getElementById('emailForm');
const clearBtn = document.getElementById('clearBtn');
const errorMessage = document.getElementById('errorMessage');
const loading = document.getElementById('loading');
const resultSection = document.getElementById('resultSection');

const fields = {
  senderName: document.getElementById('senderName'),
  senderEmail: document.getElementById('senderEmail'),
  emailBody: document.getElementById('emailBody'),
};

form.addEventListener('submit', (event) => {
  event.preventDefault();
  errorMessage.textContent = '';

  const data = getFormData();
  if (!data.senderName && !data.senderEmail && !data.emailBody) {
    errorMessage.textContent = 'Please enter email details before analysis.';
    return;
  }

  resultSection.classList.add('hidden');
  loading.classList.remove('hidden');

  setTimeout(() => {
    const report = analyzeEmail(data);
    renderReport(report);
    loading.classList.add('hidden');
    resultSection.classList.remove('hidden');
    resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, 750);
});

clearBtn.addEventListener('click', () => {
  Object.values(fields).forEach((field) => field.value = '');
  errorMessage.textContent = '';
  resultSection.classList.add('hidden');
  loading.classList.add('hidden');
});

function getFormData() {
  return {
    senderName: fields.senderName.value.trim(),
    senderEmail: fields.senderEmail.value.trim(),
    emailBody: fields.emailBody.value.trim(),
  };
}

function analyzeEmail(data) {
  let score = 0;
  const senderAnalysis = [];
  const contentAnalysis = [];
  const suspiciousPhrases = new Set();
  const suspiciousLinks = new Set();

  const senderNameLower = data.senderName.toLowerCase();
  const senderEmailLower = data.senderEmail.toLowerCase();
  const bodyLower = data.emailBody.toLowerCase();

  const trustedBrands = ['paypal', 'microsoft', 'google', 'amazon', 'apple', 'netflix', 'bank', 'university'];
  const freeProviders = ['gmail.com', 'outlook.com', 'hotmail.com', 'yahoo.com', 'protonmail.com'];
  const domain = extractDomain(senderEmailLower);

  if (data.senderEmail && !isValidEmail(data.senderEmail)) {
    score += 15;
    senderAnalysis.push('The sender email format looks invalid or incomplete.');
  }

  const claimsTrustedBrand = trustedBrands.some((brand) => senderNameLower.includes(brand));
  const usesFreeProvider = freeProviders.includes(domain);

  if (claimsTrustedBrand && usesFreeProvider) {
    score += 25;
    senderAnalysis.push('The sender name uses a trusted organization name, but the email comes from a free email provider.');
    suspiciousPhrases.add(data.senderName);
  }

  if (claimsTrustedBrand && domain && !senderNameLower.includes(domain.split('.')[0]) && !usesFreeProvider) {
    score += 15;
    senderAnalysis.push('The sender name and sender email domain may not clearly match.');
  }

  if (domain && /(security|verify|login|account|support).*(secure|update|service)|\d/.test(domain)) {
    score += 20;
    senderAnalysis.push('The sender domain contains suspicious security/account-related words or numbers.');
  }

  if (senderAnalysis.length === 0) {
    senderAnalysis.push('No major sender identity problem was detected.');
  }

  const phraseRules = [
    { phrases: ['urgent', 'immediately', 'act now', 'final warning', 'today'], points: 15, message: 'Urgency or pressure language was detected.' },
    { phrases: ['verify your account', 'confirm your account', 'update your account', 'account verification'], points: 15, message: 'Account verification pressure was detected.' },
    { phrases: ['password', 'login credentials', 'personal information', 'credit card', 'pin'], points: 25, message: 'The email asks for sensitive information or credentials.' },
    { phrases: ['bank', 'payment', 'invoice', 'refund', 'transfer', 'transaction'], points: 10, message: 'Financial or payment-related language was detected.' },
    { phrases: ['account will be suspended', 'account will be blocked', 'legal action', 'failure to act'], points: 20, message: 'Threatening language or account suspension pressure was detected.' },
    { phrases: ['congratulations', 'you won', 'free gift', 'prize'], points: 15, message: 'A too-good-to-be-true offer was detected.' },
    { phrases: ['dear customer', 'dear user'], points: 5, message: 'A generic greeting was detected.' },
    { phrases: ['click this link', 'click here', 'open the link'], points: 15, message: 'The email tries to push the user to click a link.' },
  ];

  phraseRules.forEach((rule) => {
    rule.phrases.forEach((phrase) => {
      if (bodyLower.includes(phrase)) {
        score += rule.points;
        contentAnalysis.push(rule.message);
        suspiciousPhrases.add(findOriginalPhrase(data.emailBody, phrase));
      }
    });
  });

  const links = extractLinks(data.emailBody);
  links.forEach((link) => {
    const lowerLink = link.toLowerCase();
    if (/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)/.test(lowerLink)) {
      score += 25;
      contentAnalysis.push('A shortened suspicious link was detected.');
      suspiciousLinks.add(link);
    }
    if (lowerLink.startsWith('http://')) {
      score += 10;
      contentAnalysis.push('An HTTP link was detected. HTTPS is usually safer than HTTP.');
      suspiciousLinks.add(link);
    }
  });

  if (links.length > 0 && suspiciousLinks.size === 0) {
    contentAnalysis.push('Links were found, but no shortened or HTTP-only link was detected.');
  }

  if (contentAnalysis.length === 0) {
    contentAnalysis.push('No major suspicious content pattern was detected.');
  }

  score = Math.min(score, 100);
  const riskLevel = getRiskLevel(score);

  return {
    riskLevel,
    riskScore: score,
    aiVerdict: buildVerdict(riskLevel, score),
    senderAnalysis: unique(senderAnalysis),
    contentAnalysis: unique(contentAnalysis),
    suspiciousPhrases: Array.from(suspiciousPhrases).filter(Boolean),
    suspiciousLinks: Array.from(suspiciousLinks),
    feedback: buildFeedback(riskLevel),
  };
}

function extractDomain(email) {
  if (!email.includes('@')) return '';
  return email.split('@').pop().trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function extractLinks(text) {
  return text.match(/https?:\/\/[^\s]+/gi) || [];
}

function findOriginalPhrase(body, phrase) {
  const index = body.toLowerCase().indexOf(phrase.toLowerCase());
  if (index === -1) return phrase;
  return body.substring(index, index + phrase.length);
}

function unique(items) {
  return [...new Set(items)];
}

function getRiskLevel(score) {
  if (score <= 30) return 'Safe';
  if (score <= 65) return 'Medium Risk';
  return 'High Risk';
}

function buildVerdict(level, score) {
  if (level === 'High Risk') {
    return `This email is highly suspicious. The simulated AI engine detected strong suspicious mail signals and assigned a risk score of ${score}/100.`;
  }
  if (level === 'Medium Risk') {
    return 'This email contains some suspicious signals. The user should verify the sender and avoid sharing sensitive information.';
  }
  return 'This email appears mostly safe based on the current demo analysis. No strong suspicious mail pattern was detected.';
}

function buildFeedback(level) {
  if (level === 'High Risk') {
    return 'Do not click any links, do not enter passwords, and do not share personal information. Visit the official website manually or contact the organization through verified channels.';
  }
  if (level === 'Medium Risk') {
    return 'Be careful before taking action. Verify the sender address, avoid opening suspicious links, and confirm the request through an official channel.';
  }
  return 'No immediate danger was detected. Still, always check the sender address and avoid sharing sensitive information through email.';
}

function renderReport(report) {
  const className = report.riskLevel === 'Safe' ? 'safe' : report.riskLevel === 'Medium Risk' ? 'medium' : 'high';

  document.getElementById('riskLevel').textContent = report.riskLevel;
  document.getElementById('riskScore').textContent = report.riskScore;
  document.getElementById('aiVerdict').textContent = report.aiVerdict;
  document.getElementById('feedback').textContent = report.feedback;

  const riskBanner = document.getElementById('riskBanner');
  riskBanner.className = `risk-banner ${className}`;

  const scoreBar = document.getElementById('scoreBar');
  scoreBar.className = `score-bar ${className}`;
  scoreBar.style.width = `${report.riskScore}%`;

  renderList('senderAnalysis', report.senderAnalysis);
  renderList('contentAnalysis', report.contentAnalysis);
  renderList('suspiciousPhrases', report.suspiciousPhrases.length ? report.suspiciousPhrases : ['No suspicious phrase detected.']);
  renderList('suspiciousLinks', report.suspiciousLinks.length ? report.suspiciousLinks : ['No suspicious link detected.']);
}

function renderList(elementId, items) {
  const list = document.getElementById(elementId);
  list.innerHTML = '';
  items.forEach((item) => {
    const li = document.createElement('li');
    li.textContent = item;
    list.appendChild(li);
  });
}
