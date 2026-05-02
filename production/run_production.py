import argparse
import ast
import ctypes
import importlib.util
import json
import pickle
import sys
import warnings
from pathlib import Path
from datetime import datetime, timedelta, timezone


KEEP_ASSIGNMENTS = {
    "BASE_DIR",
    "KK_FILES_DIR",
    "ANALYSIS_DIR",
    "PRODUCTION_DIR",
    "CONFIG",
    "RISK_LEVELS",
    "RISK_COLORS",
    "DASHBOARD_COLS",
    "ACTION_MAP",
    "RULE_LABELS",
    "REVIEW_TAB_BASE",
    "REVIEW_TAB",
    "REVIEW_HISTORY_TAB",
    "REVIEW_DECISIONS",
    "REVIEW_PENDING_DECISION",
    "REVIEW_FRAUD_TYPES",
    "DEFAULT_SHEET_ID",
    "CURRENT_RUN_LABEL",
    "MIN_SAMPLES_ADJUST",
    "MAX_WEIGHT_CHANGE",
    "ORIGINAL_WEIGHTS_FILE",
    "REVIEW_COLS",
    "ML_FEATURES",
}


REQUIRED_MODULES = {
    "joblib": "joblib",
    "matplotlib": "matplotlib",
    "numpy": "numpy",
    "pandas": "pandas",
    "pyarrow": "pyarrow",
    "seaborn": "seaborn",
    "sklearn": "scikit-learn",
    "google.auth": "google-auth",
    "google_auth_oauthlib": "google-auth-oauthlib",
    "gspread": "gspread",
    "gspread_dataframe": "gspread-dataframe",
}


def missing_runtime_modules() -> dict[str, str]:
    missing = {}
    for module, package in REQUIRED_MODULES.items():
        try:
            module_exists = importlib.util.find_spec(module) is not None
        except ModuleNotFoundError:
            module_exists = False
        if not module_exists:
            missing[module] = package
    return missing


def ensure_runtime_dependencies() -> None:
    missing = missing_runtime_modules()
    if not missing:
        return

    packages = " ".join(dict.fromkeys(missing.values()))
    missing_names = ", ".join(sorted(missing))
    raise RuntimeError(
        "Dependências em falta no ambiente Python atual: "
        f"{missing_names}.\n")


def configure_runtime_warnings():
    try:
        from sklearn.exceptions import InconsistentVersionWarning
    except Exception:
        InconsistentVersionWarning = None

    warnings.filterwarnings("ignore", category=FutureWarning)

    if InconsistentVersionWarning is not None:
        warnings.filterwarnings("ignore", category=InconsistentVersionWarning)


def _cell_source(cell):
    source = cell.get("source", "")
    if isinstance(source, list):
        return "".join(source)
    return source


def load_notebook_namespace(notebook_path: Path):
    notebook = json.loads(notebook_path.read_text(encoding="utf-8-sig"))
    body = []
    seen_assignments = set()

    for cell in notebook.get("cells", []):
        if cell.get("cell_type") != "code":
            continue

        source = _cell_source(cell)
        if not source.strip():
            continue

        try:
            tree = ast.parse(source, filename=f"{notebook_path.name}:{cell.get('id', 'cell')}")
        except SyntaxError:
            continue

        for node in tree.body:
            if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef)):
                body.append(node)
                continue

            if isinstance(node, ast.Assign):
                target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                keep_names = [name for name in target_names if name in KEEP_ASSIGNMENTS and name not in seen_assignments]
                if keep_names:
                    body.append(node)
                    seen_assignments.update(keep_names)
                continue

            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                if node.target.id in KEEP_ASSIGNMENTS and node.target.id not in seen_assignments:
                    body.append(node)
                    seen_assignments.add(node.target.id)

    module = ast.Module(body=body, type_ignores=[])
    ast.fix_missing_locations(module)

    namespace = {"__name__": "__fraud_production__", "_json": json,}
    exec(compile(module, str(notebook_path), "exec"), namespace)
    return namespace


def setup_google_sheets(namespace, base_dir: Path, sheet_id: str | None, sheet_tab: str | None):
    import gspread
    from gspread_dataframe import set_with_dataframe

    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request

    credentials_path = base_dir / "google_oauth_credentials.json"
    token_path = base_dir / "google_token.json"
    scopes = [
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive.file",
    ]

    creds = None
    if token_path.exists():
        try:
            with token_path.open("rb") as handle:
                creds = pickle.load(handle)
        except Exception:
            print("[AUTH] Token local inválido ou placeholder. Será necessário autenticar novamente.")
            creds = None

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), scopes)
            creds = flow.run_local_server(port=0)
        with token_path.open("wb") as handle:
            pickle.dump(creds, handle)

    namespace["gspread"] = gspread
    namespace["set_with_dataframe"] = set_with_dataframe
    namespace["creds"] = creds
    namespace["SHEET_ID"] = sheet_id or "YOUR_GOOGLE_SHEET_ID"
    namespace["SHEET_TAB"] = sheet_tab or "fraud_results_dashboard"


def show_windows_warning(title: str, message: str):
    try:
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)
    except Exception:
        print(f"[WARNING] {title}: {message}")


def confirm_windows_warning(title: str, message: str) -> bool:
    try:
        result = ctypes.windll.user32.MessageBoxW(0, message, title, 0x34)
        return result == 6 
    except Exception:
        print(f"[WARNING] {title}: {message}")
        answer = input("Continuar com a execução? [y/N]: ").strip().lower()
        return answer in {"y", "yes", "s", "sim"}



def prompt_first_run_hours(default_hours: int = 24) -> int:
    try:
        raw = input(f"Primeira execução detetada. Quantas horas para trás vamos analisar? [valor por defeito: {default_hours}]: ").strip()
    except EOFError:
        raw = ""

    if not raw:
        return int(default_hours)

    try:
        value = int(raw)
        if value <= 0:
            raise ValueError
        return value
    except ValueError:
        print(f"[SCRIPT] Valor inválido. A usar o valor por defeito de {default_hours}h.")
        return int(default_hours)

def warn_if_last_run_is_stale(config: dict) -> bool:
    production_dir = Path(config["production_dir"])
    last_run_path = production_dir / "last_run.json"
    window_days = 32

    if config.get('production_ignore_last_run'):
        return True
    if config.get('production_reference_time_mode') == 'dataset_max':
        return True

    if not last_run_path.exists():
        return True

    try:
        payload = json.loads(last_run_path.read_text(encoding="utf-8"))
        last_run_raw = payload.get("timestamp")
        if not last_run_raw:
            return True

        last_run = datetime.fromisoformat(str(last_run_raw).replace("Z", "+00:00"))
        if last_run.tzinfo is None:
            last_run = last_run.replace(tzinfo=timezone.utc)

        now_utc = datetime.now(timezone.utc)
        cutoff = now_utc - timedelta(days=window_days)

        if last_run < cutoff:
            msg = (
                "A última execução registada em production/last_run.json está fora da janela "
                f"operacional de {window_days} dias.\n\n"
                f"last_run: {last_run.isoformat()}\n"
                f"cutoff seguro: {cutoff.isoformat()}\n\n"
                "Pode haver perda de dados nesta execução porque a produção só carrega a janela recente.\n\n"
                "Continuar mesmo assim?")
            
            should_continue = confirm_windows_warning("Aviso de possível perda de dados", msg)
            
            print(f"[SCRIPT][WARNING] {msg}")
            return should_continue
        
        return True
    
    except Exception as exc:
        print(f"[SCRIPT][WARNING] Não foi possível validar last_run.json: {exc}")
        return True


def main():
    parser = argparse.ArgumentParser(description="Executa o pipeline de produção do fraud_p2_kk sem abrir o notebook.")
    parser.add_argument("--notebook", default="fraud_p2_kk.ipynb", help="Caminho para o notebook fonte.")
    parser.add_argument("--production-dir", default=None, help="Substitui o diretório de produção.")
    parser.add_argument("--window-days", type=int, default=None, help="Janela de contexto para carregar dados na produção.")
    parser.add_argument("--first-run-hours", type=int, default=None, help="Horas a considerar como 'ordens novas' quando ignoras o last_run ou não existe last_run.")
    parser.add_argument("--ignore-last-run", action="store_true", help="Ignora o last_run.json e simula uma primeira execução na janela definida.")
    parser.add_argument("--dashboard-window-days", type=int, default=None, help="Legado: a dashboard agora exporta a última execução completa.")
    parser.add_argument("--sheet-id", default=None, help="Substitui o Google Sheet ID.")
    parser.add_argument("--sheet-tab", default=None, help="Substitui o separador da dashboard.")
    parser.add_argument("--check-only", action="store_true", help="Valida dependências e carregamento do notebook sem executar produção.")
    parser.add_argument("--sync-review-only", action="store_true", help="Lê decisões do separador fraud_review e sincroniza o repositório local sem executar produção.")
    args = parser.parse_args()

    notebook_path = Path(args.notebook).resolve()
    base_dir = notebook_path.parent

    configure_runtime_warnings()
    ensure_runtime_dependencies()
    namespace = load_notebook_namespace(notebook_path)
    config = dict(namespace["CONFIG"])
    config["mode"] = "production"

    if args.production_dir:
        config["production_dir"] = args.production_dir
    if args.window_days is not None:
        config["production_window_days"] = int(args.window_days)
    if args.first_run_hours is not None:
        config["production_first_run_hours"] = int(args.first_run_hours)
    if args.ignore_last_run:
        config["production_ignore_last_run"] = True
    if args.dashboard_window_days is not None:
        config["dashboard_window_days"] = int(args.dashboard_window_days)
        config["production_gs_window_days"] = int(args.dashboard_window_days)

    if args.check_only:
        print("[SCRIPT] Check OK: dependências disponíveis e notebook carregado.")
        print(f"[SCRIPT] Notebook fonte: {notebook_path}")
        print(f"[SCRIPT] Diretório de produção: {config['production_dir']}")
        return

    setup_google_sheets(namespace, base_dir, args.sheet_id, args.sheet_tab)

    namespace["CONFIG"] = config
    namespace["ORIGINAL_WEIGHTS_FILE"] = str(Path(config["production_dir"]) / "original_weights.json")

    print("[SCRIPT] Modo de produção preparado.")
    print(f"[SCRIPT] Notebook fonte: {notebook_path}")
    print(f"[SCRIPT] Diretório de produção: {config['production_dir']}")
    print("[SCRIPT] Âmbito da dashboard: última execução de produção")
    print(f"[SCRIPT] Separador da dashboard: {namespace['SHEET_TAB']}")

    if args.sync_review_only:
        if "read_review_decisions" not in namespace:
            raise RuntimeError("Função read_review_decisions não encontrada no notebook.")
        df_reviews = namespace["read_review_decisions"](namespace["gspread"].authorize(namespace["creds"]), namespace["SHEET_ID"], config=config)
        print(f"[SCRIPT] Sincronização da review concluída: {len(df_reviews):,} decisões carregadas.")
        print(f"[SCRIPT] Repositório local: {Path(config['production_dir']) / 'review_decisions_store'}")
        return

    last_run_path = Path(config["production_dir"]) / "last_run.json"
    needs_first_run_prompt = (args.first_run_hours is None and (args.ignore_last_run or not last_run_path.exists()))
    if needs_first_run_prompt:
        chosen_hours = prompt_first_run_hours(default_hours=24)
        config["production_first_run_hours"] = int(chosen_hours)
        print(f"[SCRIPT] Janela da primeira execução escolhida: {chosen_hours}h")

    if not warn_if_last_run_is_stale(config):
        print("[SCRIPT] Execução cancelada pelo utilizador devido a risco de perda de dados.")
        return

    namespace["run_hourly_production"](config)


if __name__ == "__main__":
    main()
