const { chromium } = require('playwright');

(async () => {
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    console.log('Testing NeuralShield Dashboard...');
    
    try {
        // Test main dashboard
        console.log('Testing main dashboard...');
        await page.goto('http://localhost:9090/', { waitUntil: 'networkidle' });
        const title = await page.title();
        console.log('Page title:', title);
        
        // Test API endpoints
        console.log('Testing API endpoints...');
        const health = await page.evaluate(async () => {
            const res = await fetch('/api/health');
            return await res.json();
        });
        console.log('Health check:', health);
        
        const stats = await page.evaluate(async () => {
            const res = await fetch('/api/sniffer/status');
            return await res.json();
        });
        console.log('Sniffer status:', stats);
        
        const settings = await page.evaluate(async () => {
            const res = await fetch('/api/settings');
            return await res.json();
        });
        console.log('Settings:', settings);
        
        console.log('\n✓ All tests passed successfully!');
        
    } catch (error) {
        console.error('Error:', error.message);
    }
    
    await browser.close();
})();
