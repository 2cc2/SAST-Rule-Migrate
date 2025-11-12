import urllib.parse
import subprocess
import os

def parse_uri(uri):
    """
    Parse a URI and return its components.

    Args:
        uri (str): The URI to parse.

    Returns:
        dict: A dictionary containing the parsed components of the URI.
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'params': parsed.params,
            'query': urllib.parse.parse_qs(parsed.query),
            'fragment': parsed.fragment
        }
    except Exception as e:
        print(f"Error parsing URI: {e}")
        return None

def execute_query(parsed_uri):
    """
    Execute a query based on the parsed URI.

    Args:
        parsed_uri (dict): The parsed URI components.

    Returns:
        str: The output of the query execution.
    """
    try:
        # Example: Construct a query command based on the URI path
        query_command = ["codeql", "query", parsed_uri['path']]
        result = subprocess.run(query_command, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Query execution failed: {e}")
        return None

def parse_query_results(query_output):
    """
    Parse the query results and generate jump links.

    Args:
        query_output (str): The output from the query execution.

    Returns:
        list: A list of dictionaries containing jump link information.
    """
    try:
        # Example: Parse the output into structured data (this depends on the query output format)
        lines = query_output.splitlines()
        links = []
        for line in lines:
            # Assuming each line contains file, start_line, start_col, end_line, end_col
            parts = line.split(',')
            if len(parts) == 5:
                links.append({
                    'file': parts[0].strip(),
                    'start_line': int(parts[1].strip()),
                    'start_col': int(parts[2].strip()),
                    'end_line': int(parts[3].strip()),
                    'end_col': int(parts[4].strip())
                })
        return links
    except Exception as e:
        print(f"Error parsing query results: {e}")
        return []

def file_range_from_uri(uri):
    """
    Convert a URI to a file range.

    Args:
        uri (str): The URI to convert.

    Returns:
        dict: A dictionary containing file range information.
    """
    try:
        parsed_uri = parse_uri(uri)
        if not parsed_uri:
            return None

        # Example: Extract file range information from the URI query parameters
        query = parsed_uri.get('query', {})
        return {
            'file': parsed_uri['path'],
            'start_line': int(query.get('start_line', [0])[0]),
            'start_col': int(query.get('start_col', [0])[0]),
            'end_line': int(query.get('end_line', [0])[0]),
            'end_col': int(query.get('end_col', [0])[0])
        }
    except Exception as e:
        print(f"Error converting URI to file range: {e}")
        return None

def generate_location_links(links):
    """
    Generate VS Code LocationLink objects from parsed links.

    Args:
        links (list): A list of dictionaries containing jump link information.

    Returns:
        list: A list of LocationLink objects.
    """
    try:
        location_links = []
        for link in links:
            location_links.append({
                'targetUri': link['file'],
                'targetRange': {
                    'start': {'line': link['start_line'], 'character': link['start_col']},
                    'end': {'line': link['end_line'], 'character': link['end_col']}
                },
                'targetSelectionRange': {
                    'start': {'line': link['start_line'], 'character': link['start_col']},
                    'end': {'line': link['end_line'], 'character': link['end_col']}
                }
            })
        return location_links
    except Exception as e:
        print(f"Error generating LocationLink objects: {e}")
        return []

def parse_imports(entry_file):
    """
    Parse the import statements from the given file.

    Args:
        entry_file (str): The path to the entry file.

    Returns:
        list: A list of import paths extracted from the file.
    """
    try:
        imports = []
        with open(entry_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line.startswith("import"):
                    # Example: Extract the import path (this depends on the file format)
                    parts = line.split()
                    if len(parts) > 1:
                        imports.append(parts[1])
        return imports
    except Exception as e:
        print(f"Error parsing imports from {entry_file}: {e}")
        return []

def locate_files(imports, base_path):
    """
    Locate files based on the import paths and base path.

    Args:
        imports (list): A list of import paths.
        base_path (str): The base directory to search in.

    Returns:
        list: A list of file paths corresponding to the imports.
    """
    located_files = []
    try:
        for imp in imports:
            # Convert import path to file path (example: Java-style imports)
            file_path = os.path.join(base_path, imp.replace('.', '/') + '.ql')
            if os.path.exists(file_path):
                located_files.append(file_path)
            else:
                print(f"File not found for import: {imp}")
        return located_files
    except Exception as e:
        print(f"Error locating files: {e}")
        return []

def main():
    """
    Main function to parse imports, locate files, and print results.
    """
    entry_file = "/home/cbb/codeql/java/ql/src/Security/CWE/CWE-079/XSS.ql"
    base_path = "/home/cbb/codeql/"

    # Parse imports from the entry file
    imports = parse_imports(entry_file)
    print(imports)
    # Locate files based on imports and base path
    located_files = locate_files(imports, base_path)

    # Print results
    for file in located_files:
        print(f"📄 {file.split('/')[-1]}  |  {file} |")

    # Print warnings for missing modules
    for imp in imports:
        file_path = f"{base_path}{imp.replace('.', '/').strip()}.ql"
        if file_path not in located_files:
            print(f"[⚠️] 未找到模块: {imp} | import by {entry_file}")

if __name__ == "__main__":
    main()