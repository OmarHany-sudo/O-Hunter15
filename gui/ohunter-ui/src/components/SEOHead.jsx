import React from 'react';
import { Helmet } from 'react-helmet-async';

const SEOHead = ({ 
  title = "O-Hunter - Free Web Vulnerability Scanner", 
  description = "Professional web vulnerability scanner for security testing. Detect XSS, SQL Injection, SSRF, RCE, and more. Free community edition with advanced features.",
  keywords = "vulnerability scanner, web security, penetration testing, XSS, SQL injection, SSRF, RCE, security audit, OWASP Top 10",
  canonicalUrl = "",
  ogImage = "/og-image.png",
  structuredData = null
}) => {
  const defaultStructuredData = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    "name": "O-Hunter Web Vulnerability Scanner",
    "description": "Professional web vulnerability scanner for security testing and penetration testing",
    "applicationCategory": "SecurityApplication",
    "operatingSystem": "Web Browser",
    "offers": {
      "@type": "Offer",
      "price": "0",
      "priceCurrency": "USD"
    },
    "author": {
      "@type": "Organization",
      "name": "O-Hunter Team"
    },
    "featureList": [
      "XSS Detection",
      "SQL Injection Testing",
      "SSRF Vulnerability Scanning",
      "RCE Detection",
      "Security Headers Analysis",
      "Directory Enumeration",
      "Port Scanning",
      "Technology Stack Detection"
    ]
  };

  const finalStructuredData = structuredData || defaultStructuredData;

  return (
    <Helmet>
      {/* Basic Meta Tags */}
      <title>{title}</title>
      <meta name="description" content={description} />
      <meta name="keywords" content={keywords} />
      <meta name="author" content="O-Hunter Team" />
      <meta name="robots" content="index, follow" />
      <meta name="language" content="English" />
      
      {/* Canonical URL */}
      {canonicalUrl && <link rel="canonical" href={canonicalUrl} />}
      
      {/* Open Graph Tags */}
      <meta property="og:title" content={title} />
      <meta property="og:description" content={description} />
      <meta property="og:type" content="website" />
      <meta property="og:image" content={ogImage} />
      <meta property="og:image:alt" content="O-Hunter Web Vulnerability Scanner" />
      <meta property="og:site_name" content="O-Hunter" />
      
      {/* Twitter Card Tags */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:title" content={title} />
      <meta name="twitter:description" content={description} />
      <meta name="twitter:image" content={ogImage} />
      
      {/* Additional Meta Tags */}
      <meta name="theme-color" content="#3b82f6" />
      <meta name="msapplication-TileColor" content="#3b82f6" />
      
      {/* Structured Data */}
      <script type="application/ld+json">
        {JSON.stringify(finalStructuredData)}
      </script>
    </Helmet>
  );
};

export default SEOHead;

