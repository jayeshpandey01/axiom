with open("controller/fleet_manager.py", "r") as f:
    text = f.read()

target = """                except Exception:
                    pass

                self._write_dry_run_output(profile, target_value, output_file_path)
                return output_file_path
                # If external scanner binary is not installed, run genuine native Python probe"""

replacement = """                except Exception as exc:
                    logger.info("CLI scanner unavailable (%s); falling back to native Python probe.", exc)

                # If external scanner binary is not installed, run genuine native Python probe"""

text = text.replace(target, replacement)

with open("controller/fleet_manager.py", "w") as f:
    f.write(text)
