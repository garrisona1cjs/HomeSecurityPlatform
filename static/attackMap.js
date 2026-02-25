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

let soundEnabled = false;

// enable audio after first user interaction
document.addEventListener("click", () => {
    soundEnabled = true;
}, { once: true });

document.addEventListener("keydown", () => {
    soundEnabled = true;
}, { once: true });


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
// 🛡️ DEFENSIVE SHIELD REACTION
// ================================
function createShieldImpact(map, location) {

    const shield = L.circle(location, {
        radius: 15000,
        color: "#00ccff",
        weight: 3,
        opacity: 0.9,
        fillColor: "#00ccff",
        fillOpacity: 0.15
    }).addTo(map);

    let radius = 15000;
    let opacity = 0.9;

    function animate() {
        radius += 18000;
        opacity -= 0.05;

        shield.setRadius(radius);
        shield.setStyle({ opacity });

        if (opacity > 0) {
            requestAnimationFrame(animate);
        } else {
            map.removeLayer(shield);
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
// 🛡️ PROTECTED ZONE SHIELD DOME
// ================================
let shieldDomeLayer = null;

function createShieldDome(map, location) {

    if (shieldDomeLayer) return; // only create once

    shieldDomeLayer = L.circle(location, {
        radius: 180000,
        color: "#00ccff",
        weight: 2,
        opacity: 0.45,
        fillColor: "#00ccff",
        fillOpacity: 0.08
    }).addTo(map);

    // store base values for dynamic intensity
    shieldDomeLayer.baseOpacity = 0.45;
    shieldDomeLayer.baseWeight = 2;
    shieldDomeLayer.baseFill = 0.08;

    // subtle pulse animation
    let growing = true;
    let radius = 180000;

    function pulse() {
        radius += growing ? 1200 : -1200;

        if (radius > 200000) growing = false;
        if (radius < 170000) growing = true;

        shieldDomeLayer.setRadius(radius);
        requestAnimationFrame(pulse);
    }

    pulse();
}

// ================================
// 🛡️ DOME INTENSITY RESPONSE
// ================================
function intensifyShieldDome(severity) {

    if (!shieldDomeLayer) return;

    let glowBoost = 0.12;
    let weightBoost = 1;

    if (severity === "critical") {
        glowBoost = 0.35;
        weightBoost = 3;
    }

    shieldDomeLayer.setStyle({
        opacity: shieldDomeLayer.baseOpacity + glowBoost,
        fillOpacity: shieldDomeLayer.baseFill + glowBoost,
        weight: shieldDomeLayer.baseWeight + weightBoost
    });

    // return to normal after pulse
    setTimeout(() => {
        shieldDomeLayer.setStyle({
            opacity: shieldDomeLayer.baseOpacity,
            fillOpacity: shieldDomeLayer.baseFill,
            weight: shieldDomeLayer.baseWeight
        });
    }, severity === "critical" ? 1400 : 700);
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

    // 🛡 Ensure protected zone dome exists
    if (!window.shieldDomeInitialized) {
        createShieldDome(map, toCoords);
        window.shieldDomeInitialized = true;
    }

    const color = severityColors[severity] || "#00ffff";

    attackCount++;
    updateAttackCounter();
    // 🛡 dome reacts to incoming attack
    intensifyShieldDome(severity);

    createOriginPulse(map, fromCoords);
    createCountryAura(map, fromCoords);

 // rate-limit critical alert sound
if (severity === "critical" && soundEnabled) {

    const now = Date.now();

    if (!window.lastSoundTime) {
        window.lastSoundTime = 0;
    }

    if (now - window.lastSoundTime > 800) {  // 800ms throttle
        criticalSound.currentTime = 0;
        criticalSound.play().catch(()=>{});
        window.lastSoundTime = now;
    }
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

    // 🔥 Strong origin shockwave
    createImpactFlash(map, fromCoords, "#ff0033");

    // 🔥 Extra origin glow burst
    for (let i = 0; i < 2; i++) {
        setTimeout(() => createOriginPulse(map, fromCoords), i * 150);
    }
}

    animatePacket(map, fromCoords, toCoords, color);

    // 🛡️ Shield reacts to critical impacts
    if (severity === "critical") {
    createShieldImpact(map, toCoords);
}

createBeamTrail(map, fromCoords, toCoords, color);

}

