import dns.resolver
import json
from rich.console import Console
from rich.table import Table

console = Console()

# ---------------- DNS Check Functions ---------------- #

def get_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            text = r.to_text().strip('"')
            if "v=DMARC1" in text:
                policy = "none"
                for part in text.split(";"):
                    if part.strip().startswith("p="):
                        policy = part.strip()[2:]
                return True, text, policy
        return False, None, None
    except Exception:
        return False, None, None

def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for r in answers:
            text = r.to_text().strip('"')
            if "v=spf1" in text:
                warning = "Permissive SPF (all)" if "+all" in text or text.split()[-1] in ["~all","?all"] else None
                return True, text, warning
        return False, None, None
    except Exception:
        return False, None, None

def get_dkim(domain, selectors):
    for selector in selectors:
        try:
            answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
            for r in answers:
                text = r.to_text().strip('"')
                if "v=DKIM1" in text:
                    return True, text, selector
        except Exception:
            continue
    return False, None, None

# ---------------- Output ---------------- #

def print_results(domain, dmarc_res, spf_res, dkim_res):
    dmarc_exists, dmarc_text, dmarc_policy = dmarc_res
    spf_exists, spf_text, spf_warn = spf_res
    dkim_exists, dkim_text, dkim_selector = dkim_res

    table = Table(title=f"Email Security Audit for {domain}")
    table.add_column("Record", style="cyan", no_wrap=True)
    table.add_column("Status", style="magenta")
    table.add_column("Details / Warnings", style="yellow")

    table.add_row("DMARC", "[green]Exists[/green]" if dmarc_exists else "[red]Missing[/red]",
                  f"Policy: {dmarc_policy}\n{text_wrap(dmarc_text,50)}" if dmarc_exists else "")
    table.add_row("SPF", "[green]Exists[/green]" if spf_exists else "[red]Missing[/red]",
                  f"{text_wrap(spf_text,50)}" + (f"\n⚠️ {spf_warn}" if spf_warn else "") if spf_exists else "")
    table.add_row("DKIM", "[green]Exists[/green]" if dkim_exists else "[red]Missing[/red]",
                  f"Selector: {dkim_selector}\n{text_wrap(dkim_text,50)}" if dkim_exists else "")

    score = sum([dmarc_exists, spf_exists, dkim_exists])
    table.caption = f"Overall Email Security Score: {score}/3"
    console.print(table)

def text_wrap(text, width=60):
    import textwrap
    if text:
        return "\n".join(textwrap.wrap(text, width=width))
    return ""

# ---------------- Interactive CLI ---------------- #

def interactive_cli():
    console.print("[bold cyan]Welcome to the Email Security Audit Tool[/bold cyan]\n")

    results_list = []

    while True:
        domain_input = input("Enter a domain (or type 'exit' to quit): ").strip()
        if domain_input.lower() == "exit":
            break

        selectors_input = input("Enter DKIM selectors separated by space (press Enter for 'default'): ").strip()
        selectors = selectors_input.split() if selectors_input else ["default"]

        json_input = input("Do you want to export results to JSON? (y/n): ").strip().lower()
        export_json = json_input == "y"

        # Run checks
        dmarc_res = get_dmarc(domain_input)
        spf_res = get_spf(domain_input)
        dkim_res = get_dkim(domain_input, selectors)

        print_results(domain_input, dmarc_res, spf_res, dkim_res)

        results_list.append({
            "domain": domain_input,
            "DMARC": {"exists": dmarc_res[0], "record": dmarc_res[1], "policy": dmarc_res[2]},
            "SPF": {"exists": spf_res[0], "record": spf_res[1], "warning": spf_res[2]},
            "DKIM": {"exists": dkim_res[0], "record": dkim_res[1], "selector": dkim_res[2]},
            "score": sum([dmarc_res[0], spf_res[0], dkim_res[0]])
        })

        if export_json:
            with open("email_audit_results.json", "w") as f:
                json.dump(results_list, f, indent=4)
            console.print("[bold green]Results exported to email_audit_results.json[/bold green]")

        console.print("\n[bold yellow]--- Scan Complete ---[/bold yellow]\n")

interactive_cli()