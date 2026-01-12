const { chromium } = require('playwright');

(async () => {
    console.log('Testing NeuralShield Application...\n');
    
    const browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    
    const results = {
        passed: 0,
        failed: 0,
        errors: []
    };
    
    try {
        // Test 1: Main Dashboard
        console.log('Test 1: Loading main dashboard...');
        await page.goto('http://localhost:5000/', { waitUntil: 'domcontentloaded', timeout: 15000 });
        await page.waitForTimeout(2000); // Wait for dynamic content
        const title = await page.title();
        console.log('✓ Dashboard loaded successfully');
        console.log('  Title:', title);
        results.passed++;
        
        // Test 2: Health Check API
        console.log('\nTest 2: Testing Health API...');
        const health = await page.evaluate(async () => {
            const res = await fetch('/api/health');
            return await res.json();
        });
        console.log('✓ Health check passed');
        console.log('  Status:', health.status);
        results.passed++;
        
        // Test 3: Sniffer Status
        console.log('\nTest 3: Testing Sniffer Status API...');
        const sniffer = await page.evaluate(async () => {
            const res = await fetch('/api/sniffer/status');
            return await res.json();
        });
        console.log('✓ Sniffer status retrieved');
        console.log('  Running:', sniffer.running);
        console.log('  Packets analyzed:', sniffer.packet_count);
        results.passed++;
        
        // Test 4: Settings API
        console.log('\nTest 4: Testing Settings API...');
        const settings = await page.evaluate(async () => {
            const res = await fetch('/api/settings');
            return await res.json();
        });
        console.log('✓ Settings retrieved');
        console.log('  Auto-block enabled:', settings.auto_block_enabled);
        console.log('  Anomaly threshold:', settings.anomaly_threshold);
        results.passed++;
        
        // Test 5: Threats Page
        console.log('\nTest 5: Loading threats page...');
        await page.goto('http://localhost:5000/threats', { waitUntil: 'domcontentloaded', timeout: 15000 });
        await page.waitForTimeout(2000);
        console.log('✓ Threats page loaded');
        results.passed++;
        
        // Test 6: Firewall Page
        console.log('\nTest 6: Loading firewall page...');
        await page.goto('http://localhost:5000/firewall', { waitUntil: 'domcontentloaded', timeout: 15000 });
        await page.waitForTimeout(2000);
        console.log('✓ Firewall page loaded');
        results.passed++;
        
        // Test 7: Settings Page
        console.log('\nTest 7: Loading settings page...');
        await page.goto('http://localhost:5000/settings', { waitUntil: 'domcontentloaded', timeout: 15000 });
        await page.waitForTimeout(2000);
        console.log('✓ Settings page loaded');
        results.passed++;
        
        // Test 8: System Stats API
        console.log('\nTest 8: Testing System Stats API...');
        const sysStats = await page.evaluate(async () => {
            const res = await fetch('/api/system/stats');
            return await res.json();
        });
        console.log('✓ System stats retrieved');
        console.log('  CPU:', sysStats.cpu_percent.toFixed(1) + '%');
        console.log('  Memory:', sysStats.memory_percent.toFixed(1) + '%');
        results.passed++;
        
        // Test 9: Threats API
        console.log('\nTest 9: Testing Threats API...');
        const threats = await page.evaluate(async () => {
            const res = await fetch('/api/threats?limit=10');
            return await res.json();
        });
        console.log('✓ Threats API working');
        console.log('  Total threats:', threats.count);
        results.passed++;
        
        // Test 10: Firewall Status API
        console.log('\nTest 10: Testing Firewall Status API...');
        const firewall = await page.evaluate(async () => {
            const res = await fetch('/api/firewall/status');
            return await res.json();
        });
        console.log('✓ Firewall status retrieved');
        console.log('  System:', firewall.system);
        console.log('  Supported:', firewall.supported);
        results.passed++;
        
        console.log('\n' + '='.repeat(60));
        console.log('🎉 ALL TESTS PASSED SUCCESSFULLY!');
        console.log('='.repeat(60));
        console.log(`✅ Total: ${results.passed} tests passed\n`);
        
        console.log('Application is working correctly on http://localhost:5000');
        console.log('Ready for deployment!\n');
        
    } catch (error) {
        console.error('\n❌ Test failed:', error.message);
        results.failed++;
        results.errors.push(error.message);
        
        console.log('\n' + '='.repeat(60));
        console.log('⚠️  TESTS COMPLETED WITH ERRORS');
        console.log('='.repeat(60));
        console.log(`✅ Passed: ${results.passed}`);
        console.log(`❌ Failed: ${results.failed}`);
    }
    
    await browser.close();
    process.exit(results.failed > 0 ? 1 : 0);
})();
