*** Begin Patch
*** Update File: src/eva/telemetry/metrics.py
@@
     try:
         httpx.post(
             endpoint,
             json={"metrics": [record]},
             timeout=3.0,
             headers={"User-Agent": "Eva-Telemetry/1.0"},
         )
-    except Exception as exc:
-        logger.debug("Telemetry export POST to %s failed: %s", endpoint, exc)
+    except (OSError, httpx.HTTPError) as exc:
+        # Narrow exception handling to expected HTTP/client errors and log for diagnostics
+        logger.debug("Telemetry export POST to %s failed: %s", endpoint, exc)
*** End Patch
