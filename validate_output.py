#!/usr/bin/env python3
"""
Output Verification Script

This script calls the SQL injection test from sql_injection.py, captures its output,
and compares it with the expected sample output to verify the vulnerability exists.

It prints a confirmation message if the output matches exactly, or displays an error
message if there is any discrepancy.
"""

import subprocess
import sys
import difflib

# Import the SQL injection function directly
from sql_injection import perform_sql_injection

# The expected output from the SQL injection test
EXPECTED_OUTPUT = '''<!doctype html>
<html lang=en>
  <head>
    <title>sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: "'name1''"
[SQL: SELECT * FROM users WHERE username = 'name1'']
(Background on this error at: https://sqlalche.me/e/20/e3q8)
 // Werkzeug Debugger</title>
    <link rel="stylesheet" href="?__debugger__=yes&amp;cmd=resource&amp;f=style.css">
    <link rel="shortcut icon"
        href="?__debugger__=yes&amp;cmd=resource&amp;f=console.png">
    <script src="?__debugger__=yes&amp;cmd=resource&amp;f=debugger.js"></script>
    <script>
      var CONSOLE_MODE = false,
          EVALEX = true,
          EVALEX_TRUSTED = false,
          SECRET = "FMi8iniGl9y40dlmZTwG";
    </script>
  </head>
  <body style="background-color: #fff">
    <div class="debugger">
<h1>OperationalError</h1>
<div class="detail">
  <p class="errormsg">sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token: &#34;&#39;name1&#39;&#39;&#34;
[SQL: SELECT * FROM users WHERE username = &#39;name1&#39;&#39;]
(Background on this error at: https://sqlalche.me/e/20/e3q8)
</p>
</div>
<h2 class="traceback">Traceback <em>(most recent call last)</em></h2>
<div class="traceback">
  <h3></h3>
  <ul><li><div class="frame" id="frame-281473389385696">
  <h4>File <cite class="filename">"/usr/local/lib/python3.11/site-packages/sqlalchemy/engine/base.py"</cite>,
      line <em class="line">1964</em>,
      in <code class="function">_exec_single_context</code></h4>
  <div class="source library"><pre class="line before"><span class="ws">                            </span>context,</pre>
<pre class="line before"><span class="ws">                        </span>):</pre>
<pre class="line before"><span class="ws">                            </span>evt_handled = True</pre>
<pre class="line before"><span class="ws">                            </span>break</pre>
<pre class="line before"><span class="ws">                </span>if not evt_handled:</pre>
<pre class="line current"><span class="ws">                    </span>self.dialect.do_execute(
<span class="ws">                    </span>^</pre>
<pre class="line after"><span class="ws">                        </span>cursor, str_statement, effective_parameters, context</pre>
<pre class="line after"><span class="ws">                    </span>)</pre>
<pre class="line after"><span class="ws"></span> </pre>
<pre class="line after"><span class="ws">            </span>if self._has_events or self.engine._has_events:</pre>
<pre class="line after"><span class="ws">                </span>self.dispatch.after_cursor_execute(</pre></div>
</div>'''

def validate_output():
    """
    Validates the output of the SQL injection test against the expected output.
    
    Returns:
        bool: True if the output matches exactly, False otherwise
    """
    try:
        # Method 1: Call the function directly
        actual_output = perform_sql_injection()
        
        # Method 2: Run as a subprocess (alternative approach)
        # process = subprocess.run(
        #     [sys.executable, 'sql_injection.py'],
        #     capture_output=True,
        #     text=True,
        #     check=True
        # )
        # actual_output = process.stdout
        
        # Compare the actual output with the expected output
        if actual_output == EXPECTED_OUTPUT:
            return True
        else:
            # Find differences for detailed error reporting
            diff = list(difflib.unified_diff(
                EXPECTED_OUTPUT.splitlines(),
                actual_output.splitlines(),
                lineterm=''
            ))
            return False, diff
    except Exception as e:
        print(f"Error validating output: {e}", file=sys.stderr)
        return False, [str(e)]

def main():
    """
    Main function to validate the SQL injection test output.
    """
    print("Validating SQL injection test output...")
    result = validate_output()
    
    if isinstance(result, tuple):
        success, diff = result
        print("❌ Validation failed! Output does not match expected output.")
        print("\nDifferences found:")
        for line in diff[:20]:  # Show first 20 diff lines to avoid overwhelming output
            print(line)
        if len(diff) > 20:
            print(f"...and {len(diff) - 20} more differences")
        sys.exit(1)
    else:
        print("✅ Validation successful! Output matches expected output exactly.")

if __name__ == "__main__":
    main()