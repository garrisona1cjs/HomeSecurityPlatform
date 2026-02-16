// =======================================
// LayerSeven Threat Intelligence Engine
// =======================================


// ================================
// CONFIG
// ================================
const severityColors = {
    critical: "#ff0033",
    high: "#ff6600",
    medium: "#00ffff",
    low: "#00ccff"
};

// track origin activity intensity
let originIntensity = {};
let activeOrigins = {};
let attackCount = 0;


// ================================
// 🔊 SOUND ALERTS
// ================================
const criticalSound = new Audio("https://actions.google.com/sounds/v1/alarms/beep_short.ogg");
criticalSound.volume = 0.3;


// ================================
// 📊 LIVE ATTACK COUNTER
// ================================
function updateAttackCounter() {

    let counter = document.getElementById("attackCounter");

    if (!counter) {
        counter = document.createElement("div");
        counter.id = "attackCounter";

        counter.style.position = "absolute";
        counter.style.top = "10px";
        counter.style.right = "15px";
        counter.style.color = "#00ffff";
        counter.style.fontFamily = "monospace";
        counter.style.fontSize = "18px";
        counter.style.zIndex = "999";

        document.body.appendChild(counter);
    }

    counter.innerHTML = "⚡ ATTACKS: " + attackCount;
}


// ================================
// 🟢 ORIGIN HEAT GLOW
// ================================
function createOriginPulse(map, location) {

    const key = location.toString();

    if (!originIntensity[key]) originIntensity[key] = 1;
    else originIntensity[key]++;

    const intensity = Math.min(originIntensity[key], 8);

    const glowColor = `rgba(255, 60, 60, ${0.1 + intensity * 0.08})`;

    const aura = L.circle(location, {
        radius: 25000 + intensity * 6000,
        color: glowColor,
        weight: 0,
        fillColor: glowColor,
        fillOpacity: 0.25
    }).addTo(map);

    setTimeout(() => map.removeLayer(aura), 1200);
}


// ================================
// 🌍 COUNTRY AURA EFFECT
// ================================
function createCountryAura(map, location) {

    const aura = L.circle(location, {
        radius: 90000,
        color: "rgba(255,0,0,0.15)",
        weight: 0,
        fillColor: "rgba(255,0,0,0.15)",
        fillOpacity: 0.15
    }).addTo(map);

    setTimeout(() => map.removeLayer(aura), 2000);
}


// ================================
// 💥 IMPACT FLASH
// ================================
function createImpactFlash(map, location, color) {

    const ring = L.circle(location, {
        radius: 20000,
        color: color,
        weight: 2,
        opacity: 0.7,
        fillOpacity: 0
    }).addTo(map);

    let radius = 20000;

    function animate() {
        radius += 16000;
        ring.setRadius(radius);
        ring.setStyle({ opacity: ring.options.opacity - 0.05 });

        if (ring.options.opacity > 0) {
            requestAnimationFrame(animate);
        } else {
            map.removeLayer(ring);
        }
    }

    animate();
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

    function move() {
        progress += 0.02;

        const lat = from[0] + (to[0] - from[0]) * progress;
        const lng = from[1] + (to[1] - from[1]) * progress;

        packet.setLatLng([lat, lng]);

        if (progress < 1) requestAnimationFrame(move);
        else {
            map.removeLayer(packet);
            createImpactFlash(map, to, color);
        }
    }

    move();
}


// ================================
// 🌊 FLOWING TRAFFIC STREAM
// ================================
function createBeamTrail(map, from, to, color) {

    const particles = 8;

    for (let i = 0; i < particles; i++) {

        let progress = Math.random();

        function animate() {

            progress += 0.015;
            if (progress > 1) progress = 0;

            const lat = from[0] + (to[0] - from[0]) * progress;
            const lng = from[1] + (to[1] - from[1]) * progress;

            const dot = L.circleMarker([lat, lng], {
                radius: 1.5,
                color: color,
                fillColor: color,
                fillOpacity: 0.8,
                interactive: false
            }).addTo(map);

            setTimeout(() => map.removeLayer(dot), 180);
            requestAnimationFrame(animate);
        }

        animate();
    }
}


// ================================
// ⚠️ CRITICAL PULSE
// ================================
function pulseBeam(line) {

    let opacity = 0.2;
    let grow = true;

    function animate() {
        opacity += grow ? 0.02 : -0.02;
        if (opacity >= 0.4) grow = false;
        if (opacity <= 0.15) grow = true;

        line.setStyle({ opacity });
        requestAnimationFrame(animate);
    }

    animate();
}


// ================================
// 🔥 DRAW ADVANCED BEAM
// ================================
function drawAttackBeam(map, fromCoords, toCoords, severity="medium") {

    const color = severityColors[severity] || "#00ffff";

    attackCount++;
    updateAttackCounter();

    createOriginPulse(map, fromCoords);
    createCountryAura(map, fromCoords);

    if (severity === "critical") {
        criticalSound.play();
    }

    const glow = L.polyline([fromCoords, toCoords], {
        color: color,
        weight: severity === "critical" ? 4 : 2,
        opacity: severity === "critical" ? 0.18 : 0.10
    }).addTo(map);

    const segments = 14;

    for (let i = 0; i < segments; i++) {

        const startLat = fromCoords[0] + (toCoords[0] - fromCoords[0]) * (i / segments);
        const startLng = fromCoords[1] + (toCoords[1] - fromCoords[1]) * (i / segments);

        const endLat = fromCoords[0] + (toCoords[0] - fromCoords[0]) * ((i+1) / segments);
        const endLng = fromCoords[1] + (toCoords[1] - fromCoords[1]) * ((i+1) / segments);

        const opacity = 0.15 + (i / segments) * 0.85;

        L.polyline([[startLat,startLng],[endLat,endLng]], {
            color: color,
            weight: 1,
            opacity: opacity,
            interactive: false
        }).addTo(map);
    }

    if (severity === "critical") {
        pulseBeam(glow);
    }

    animatePacket(map, fromCoords, toCoords, color);
    createBeamTrail(map, fromCoords, toCoords, color);
}