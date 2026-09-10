with open("controller/fleet_manager.py", "r") as f:
    text = f.read()

target = """                except Exception as probe_err:
                    logger.warning("Native probe failed for %s (%s): %s. Falling back to dry-run output.", profile.name, target_value, probe_err)
                    self._write_dry_run_output(profile, target_value, output_file_path)
                    return output_file_path"""

replacement = """                except Exception as probe_err:
                    logger.error("Native probe failed for %s (%s): %s", profile.name, target_value, probe_err)
                    raise FleetError(f"Scan failed natively for {target_value}: {probe_err}") from probe_err"""

if target in text:
    text = text.replace(target, replacement)
else:
    print("TARGET NOT FOUND in DAST section")

# Now check the SAST section
sast_target = """                except Exception as exc:
                    logger.info("CLI SAST scanner not usable (%s); running native live SAST scan.", exc)
                return self._run_native_sast_scan(target_value, profile, output_file_path)"""
# Wait, the sast section returns the native scan, it doesn't fall back to dry run if it fails. That is fine.

with open("controller/fleet_manager.py", "w") as f:
    f.write(text)
