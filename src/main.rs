#[derive(Debug)]
struct PortaAlvo {
    porta: u16,
    servico: String,
    aberta: bool,
}

struct AnalisadorDeRiscos;

impl AnalisadorDeRiscos {
    fn avaliar_risco(&self, alvo: &PortaAlvo) -> (&str, &str) {
        if !alvo.aberta {
            return ("Baixo", "Porta fechada, sem exposição direta.");
        }

        match alvo.porta {
            21 => ("Alto", "FTP vulnerável a ataques de força bruta e sniffing."),
            22 => ("Médio", "SSH aberto. Garanta autenticação por chave pública e desative root."),
            80 => ("Médio", "HTTP sem criptografia. Considere redirecionar para HTTPS (443)."),
            443 => ("Baixo", "HTTPS seguro, mas verifique certificados expirados."),
            3306 | 5432 => ("Crítico", "Banco de dados exposto diretamente à rede externa! Risco grave."),
            _ => ("Desconhecido", "Serviço não catalogado. Requer inspeção manual de pacotes."),
        }
    }
}

fn main() {
    println!("[+] Iniciando varredura inteligente de cibersegurança...\n");

    let portas_analisadas = vec![
        PortaAlvo { porta: 21, servico: String::from("FTP"), aberta: true },
        PortaAlvo { porta: 22, servico: String::from("SSH"), aberta: true },
        PortaAlvo { porta: 3306, servico: String::from("MySQL"), aberta: true },
        PortaAlvo { porta: 80, servico: String::from("HTTP"), aberta: false },
    ];

    let ia_analista = AnalisadorDeRiscos;

    println!("{:<8} | {:<10} | {:<10} | {}", "PORTA", "SERVIÇO", "RISCO", "RECOMENDAÇÃO DA IA");
    println!("----------------------------------------------------------------------------------");

    for alvo in &portas_analisadas {
        let (risco, recomendacao) = ia_analista.avaliar_risco(alvo);
        
        println!(
            "{:<8} | {:<10} | {:<10} | {}",
            alvo.porta, alvo.servico, risco, recomendacao
        );
    }

    println!("\n[+] Análise concluída com sucesso.");
}