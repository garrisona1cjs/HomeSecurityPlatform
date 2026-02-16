// =======================================
// LayerSeven Advanced Neon Attack Renderer
// FULL SOC VISUAL ENGINE
// =======================================


// ================================
// SEVERITY COLORS
// ================================
const severityColors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};

// prevent duplicate origin pulses
let activeOrigins = {};


// ================================
// 🟢 ORIGIN PULSE GLOW
// ================================
function createOriginPulse(map, location) {

    const key = location.toString();
    if (activeOrigins[key]) return;

    const pulseColor = "#00ff88";

    const center = L.circleMarker(location, {
        radius: 7,
        color: pulseColor,
        fillColor: pulseColor,
        fillOpacity: 1
    }).addTo(map);

    const ring = L.circle(location, {
        radius: 18000,
        color: pulseColor,
        weight: 2,
        opacity: 0.65,
        fillOpacity: 0
    }).addTo(map);

    let radius = 18000;
    let opacity = 0.65;

    function animatePulse() {
        radius += 900;
        opacity -= 0.012;

        ring.setRadius(radius);
        ring.setStyle({ opacity: opacity });

        if (opacity <= 0) {
            radius = 18000;
            opacity = 0.65;
        }

        requestAnimationFrame(animatePulse);
    }

    animatePulse();
    activeOrigins[key] = true;
}


// ================================
// 💥 IMPACT FLASH + SHOCKWAVE
// ================================
function createImpactFlash(map, location, color) {

    const flash = L.circleMarker(location, {
        radius: 7,
        color: color,
        fillColor: color,
        fillOpacity: 0.9
    }).addTo(map);

    const ring = L.circle(location, {
        radius: 20000,
        color: color,
        weight: 2,
        opacity: 0.6,
        fillOpacity: 0
    }).addTo(map);

    let opacity = 0.9;
    let radius = 20000;

    function animateImpact() {

        opacity -= 0.05;
        radius += 18000;

        flash.setStyle({ fillOpacity: opacity, opacity: opacity });
        ring.setStyle({ opacity: opacity });
        ring.setRadius(radius);

        if (opacity > 0) {
            requestAnimationFrame(animateImpact);
        } else {
            map.removeLayer(flash);
            map.removeLayer(ring);
        }
    }

    animateImpact();
}


// ================================
// ⚡ PACKET MOVEMENT
// ================================
function animatePacket(map, from, to, color) {

    let progress = 0;

    const packet = L.circleMarker(from, {
        radius: 3,
        color: color,
        fillColor: color,
        fillOpacity: 1
    }).addTo(map);

    function movePacket() {

        progress += 0.02;

        const lat = from[0] + (to[0] - from[0]) * progress;
        const lng = from[1] + (to[1] - from[1]) * progress;

        packet.setLatLng([lat, lng]);

        if (progress < 1) {
            requestAnimationFrame(movePacket);
        } else {
            map.removeLayer(packet);
            createImpactFlash(map, to, color);
        }
    }

    movePacket();
}


// ================================
// 🌊 BEAM TRAIL PARTICLE STREAM
// ================================
function createBeamTrail(map, from, to, color) {

    const particles = [];
    const particleCount = 8;

    for (let i = 0; i < particleCount; i++) {
        particles.push({ progress: Math.random() });
    }

    function animateParticles() {

        particles.forEach(p => {

            p.progress += 0.015;
            if (p.progress > 1) p.progress = 0;

            const lat = from[0] + (to[0] - from[0]) * p.progress;
            const lng = from[1] + (to[1] - from[1]) * p.progress;

            const dot = L.circleMarker([lat, lng], {
                radius: 1.5,
                color: color,
                fillColor: color,
                fillOpacity: 0.8,
                interactive: false
            }).addTo(map);

            setTimeout(() => map.removeLayer(dot), 180);
        });

        requestAnimationFrame(animateParticles);
    }

    animateParticles();
}


// ================================
// ⚠️ CRITICAL BEAM PULSE
// ================================
function pulseBeam(line) {

    let growing = true;
    let opacity = 0.15;

    function animate() {

        if (growing) {
            opacity += 0.02;
            if (opacity >= 0.35) growing = false;
        } else {
            opacity -= 0.02;
            if (opacity <= 0.15) growing = true;
        }

        line.setStyle({ opacity: opacity });

        requestAnimationFrame(animate);
    }

    animate();
}


// ================================
// 🔥 ADVANCED NEON ATTACK BEAM
// ================================
function drawAttackBeam(map, fromCoords, toCoords, severity = "medium") {

    const baseColor = severityColors[severity] || "#00ffff";

    // glow intensity by severity
    const glowSettings = {
        critical: { weight: 4, opacity: 0.15 },
        high:     { weight: 3.5, opacity: 0.12 },
        medium:   { weight: 3, opacity: 0.09 },
        low:      { weight: 2.5, opacity: 0.06 }
    };

    const glow = glowSettings[severity] || glowSettings.medium;

    // origin pulse
    createOriginPulse(map, fromCoords);

    // subtle glow aura
    const glowLine = L.polyline([fromCoords, toCoords], {
        color: baseColor,
        weight: glow.weight,
        opacity: glow.opacity,
        interactive: false
    }).addTo(map);

    // gradient fade beam (directional)
    const segments = 14;

    for (let i = 0; i < segments; i++) {

        const startLat = fromCoords[0] + (toCoords[0] - fromCoords[0]) * (i / segments);
        const startLng = fromCoords[1] + (toCoords[1] - fromCoords[1]) * (i / segments);

        const endLat = fromCoords[0] + (toCoords[0] - fromCoords[0]) * ((i + 1) / segments);
        const endLng = fromCoords[1] + (toCoords[1] - fromCoords[1]) * ((i + 1) / segments);

        const opacity = 0.15 + (i / segments) * 0.85;

        L.polyline([[startLat, startLng], [endLat, endLng]], {
            color: baseColor,
            weight: 1,
            opacity: opacity,
            interactive: false
        }).addTo(map);
    }

    // pulse effect for critical attacks
    if (severity === "critical") {
        pulseBeam(glowLine);
    }

    // packet + stream
    animatePacket(map, fromCoords, toCoords, baseColor);
    createBeamTrail(map, fromCoords, toCoords, baseColor);
}