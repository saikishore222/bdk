// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
#![allow(missing_docs)]

#[cfg(test)]
#[cfg(feature = "test-blockchains")]
pub mod blockchain_tests;

use bitcoin::{Address, Txid};

#[derive(Clone, Debug)]
pub struct TestIncomingInput {
    pub txid: Txid,
    pub vout: u32,
    pub sequence: Option<u32>,
}

impl TestIncomingInput {
    pub fn new(txid: Txid, vout: u32, sequence: Option<u32>) -> Self {
        Self {
            txid,
            vout,
            sequence,
        }
    }

    #[cfg(feature = "test-blockchains")]
    pub fn into_raw_tx_input(self) -> bitcoincore_rpc::json::CreateRawTransactionInput {
        bitcoincore_rpc::json::CreateRawTransactionInput {
            txid: self.txid,
            vout: self.vout,
            sequence: self.sequence,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TestIncomingOutput {
    pub value: u64,
    pub to_address: String,
}

impl TestIncomingOutput {
    pub fn new(value: u64, to_address: Address) -> Self {
        Self {
            value,
            to_address: to_address.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TestIncomingTx {
    pub input: Vec<TestIncomingInput>,
    pub output: Vec<TestIncomingOutput>,
    pub min_confirmations: Option<u64>,
    pub locktime: Option<i64>,
    pub replaceable: Option<bool>,
}

impl TestIncomingTx {
    pub fn new(
        input: Vec<TestIncomingInput>,
        output: Vec<TestIncomingOutput>,
        min_confirmations: Option<u64>,
        locktime: Option<i64>,
        replaceable: Option<bool>,
    ) -> Self {
        Self {
            input,
            output,
            min_confirmations,
            locktime,
            replaceable,
        }
    }

    pub fn add_input(&mut self, input: TestIncomingInput) {
        self.input.push(input);
    }

    pub fn add_output(&mut self, output: TestIncomingOutput) {
        self.output.push(output);
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! testutils {
    ( @external $descriptors:expr, $child:expr ) => ({
        use $crate::bitcoin::secp256k1::Secp256k1;
        use $crate::miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorTrait};

        use $crate::descriptor::AsDerived;

        let secp = Secp256k1::new();

        let parsed = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &$descriptors.0).expect("Failed to parse descriptor in `testutils!(@external)`").0;
        parsed.as_derived($child, &secp).address(bitcoin::Network::Regtest).expect("No address form")
    });
    ( @internal $descriptors:expr, $child:expr ) => ({
        use $crate::bitcoin::secp256k1::Secp256k1;
        use $crate::miniscript::descriptor::{Descriptor, DescriptorPublicKey, DescriptorTrait};

        use $crate::descriptor::AsDerived;

        let secp = Secp256k1::new();

        let parsed = Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &$descriptors.1.expect("Missing internal descriptor")).expect("Failed to parse descriptor in `testutils!(@internal)`").0;
        parsed.as_derived($child, &secp).address($crate::bitcoin::Network::Regtest).expect("No address form")
    });
    ( @e $descriptors:expr, $child:expr ) => ({ testutils!(@external $descriptors, $child) });
    ( @i $descriptors:expr, $child:expr ) => ({ testutils!(@internal $descriptors, $child) });
    ( @addr $addr:expr ) => ({ $addr });

    ( @tx ( $( ( $( $addr:tt )* ) => $amount:expr ),+ ) $( ( @inputs $( ($txid:expr, $vout:expr) ),+ ) )? $( ( @locktime $locktime:expr ) )? $( ( @confirmations $confirmations:expr ) )? $( ( @replaceable $replaceable:expr ) )? ) => ({
        let outs = vec![$( $crate::testutils::TestIncomingOutput::new($amount, testutils!( $($addr)* ))),+];
        let _ins: Vec<$crate::testutils::TestIncomingInput> = vec![];
        $(
            let _ins = vec![$( $crate::testutils::TestIncomingInput { txid: $txid, vout: $vout, sequence: None }),+];
        )?

        let locktime = None::<i64>$(.or(Some($locktime)))?;

        let min_confirmations = None::<u64>$(.or(Some($confirmations)))?;
        let replaceable = None::<bool>$(.or(Some($replaceable)))?;

        $crate::testutils::TestIncomingTx::new(_ins, outs, min_confirmations, locktime, replaceable)
    });

    ( @literal $key:expr ) => ({
        let key = $key.to_string();
        (key, None::<String>, None::<String>)
    });
    ( @generate_xprv $( $external_path:expr )? $( ,$internal_path:expr )? ) => ({
        use rand::Rng;

        let mut seed = [0u8; 32];
        rand::thread_rng().fill(&mut seed[..]);

        let key = $crate::bitcoin::util::bip32::ExtendedPrivKey::new_master(
            $crate::bitcoin::Network::Testnet,
            &seed,
        );

        let external_path = None::<String>$(.or(Some($external_path.to_string())))?;
        let internal_path = None::<String>$(.or(Some($internal_path.to_string())))?;

        (key.unwrap().to_string(), external_path, internal_path)
    });
    ( @generate_wif ) => ({
        use rand::Rng;

        let mut key = [0u8; $crate::bitcoin::secp256k1::constants::SECRET_KEY_SIZE];
        rand::thread_rng().fill(&mut key[..]);

        ($crate::bitcoin::PrivateKey {
            compressed: true,
            network: $crate::bitcoin::Network::Testnet,
            key: $crate::bitcoin::secp256k1::SecretKey::from_slice(&key).unwrap(),
        }.to_string(), None::<String>, None::<String>)
    });

    ( @keys ( $( $alias:expr => ( $( $key_type:tt )* ) ),+ ) ) => ({
        let mut map = std::collections::HashMap::new();
        $(
            let alias: &str = $alias;
            map.insert(alias, testutils!( $($key_type)* ));
        )+

        map
    });

    ( @descriptors ( $external_descriptor:expr ) $( ( $internal_descriptor:expr ) )? $( ( @keys $( $keys:tt )* ) )* ) => ({
        use std::str::FromStr;
        use std::collections::HashMap;
        use $crate::miniscript::descriptor::Descriptor;
        use $crate::miniscript::TranslatePk;

        #[allow(unused_assignments, unused_mut)]
        let mut keys: HashMap<&'static str, (String, Option<String>, Option<String>)> = HashMap::new();
        $(
            keys = testutils!{ @keys $( $keys )* };
        )*

        let external: Descriptor<String> = FromStr::from_str($external_descriptor).unwrap();
        let external: Descriptor<String> = external.translate_pk_infallible::<_, _>(|k| {
            if let Some((key, ext_path, _)) = keys.get(&k.as_str()) {
                format!("{}{}", key, ext_path.as_ref().unwrap_or(&"".into()))
            } else {
                k.clone()
            }
        }, |kh| {
            if let Some((key, ext_path, _)) = keys.get(&kh.as_str()) {
                format!("{}{}", key, ext_path.as_ref().unwrap_or(&"".into()))
            } else {
                kh.clone()
            }

        });
        let external = external.to_string();

        let internal = None::<String>$(.or({
            let string_internal: Descriptor<String> = FromStr::from_str($internal_descriptor).unwrap();

            let string_internal: Descriptor<String> = string_internal.translate_pk_infallible::<_, _>(|k| {
                if let Some((key, _, int_path)) = keys.get(&k.as_str()) {
                    format!("{}{}", key, int_path.as_ref().unwrap_or(&"".into()))
                } else {
                    k.clone()
                }
            }, |kh| {
                if let Some((key, _, int_path)) = keys.get(&kh.as_str()) {
                    format!("{}{}", key, int_path.as_ref().unwrap_or(&"".into()))
                } else {
                    kh.clone()
                }
            });
            Some(string_internal.to_string())
        }))?;

        (external, internal)
    })
}

#[macro_export]
#[doc(hidden)]
/// Macro for getting a wallet for use in a doctest
macro_rules! doctest_wallet {
    () => {{
        use $crate::bitcoin::Network;
        use $crate::database::MemoryDatabase;
        use $crate::testutils;
        let descriptor = "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)";
        let descriptors = testutils!(@descriptors (descriptor) (descriptor));

        let mut db = MemoryDatabase::new();
        let txid = populate_test_db!(
            &mut db,
            testutils! {
                @tx ( (@external descriptors, 0) => 500_000 ) (@confirmations 1)
            },
            Some(100),
        );

        $crate::Wallet::new(
            &descriptors.0,
            descriptors.1.as_ref(),
            Network::Regtest,
            db
        )
        .unwrap()
    }}
}

#[cfg(test)]
pub mod helpers {
    use super::*;
    use crate::{
        database::{AnyDatabase, BatchOperations, MemoryDatabase},
        BlockTime, KeychainKind, LocalUtxo, TransactionDetails, Wallet,
    };
    use bitcoin::{Address, Network, OutPoint, Transaction, TxIn, TxOut, Txid};
    use std::str::FromStr;

    /// Populate a test database with a `TestIncomingTx`, as if we had found the tx with a `sync`.
    /// This is a hidden function, only useful for `DataBase` unit testing.
    pub(crate) fn populate_test_db(
        db: &mut impl BatchOperations,
        tx_meta: TestIncomingTx,
        current_height: u32,
        is_coinbase: bool,
    ) -> Txid {
        // Ignore `tx_meta` inputs while creating a coinbase transaction
        let input = if is_coinbase {
            // `TxIn::default()` creates a coinbase input, by definition.
            vec![TxIn::default()]
        } else {
            tx_meta
                .input
                .iter()
                .map(|test_input| {
                    let mut txin = TxIn::default();
                    txin.previous_output = OutPoint {
                        txid: test_input.txid,
                        vout: test_input.vout,
                    };

                    if let Some(seq) = test_input.sequence {
                        txin.sequence = seq;
                    }
                    txin
                })
                .collect()
        };

        let output = tx_meta
            .output
            .iter()
            .map(|out_meta| TxOut {
                value: out_meta.value,
                script_pubkey: Address::from_str(&out_meta.to_address)
                    .unwrap()
                    .script_pubkey(),
            })
            .collect();

        let tx = Transaction {
            version: 1,
            lock_time: 0,
            input,
            output,
        };

        let txid = tx.txid();
        let confirmation_time = tx_meta.min_confirmations.map(|conf| BlockTime {
            height: current_height.checked_sub(conf as u32).unwrap(),
            timestamp: 0,
        });

        let tx_details = TransactionDetails {
            transaction: Some(tx.clone()),
            txid,
            fee: Some(0),
            received: 0,
            sent: 0,
            confirmation_time,
        };

        db.set_tx(&tx_details).unwrap();
        for (vout, out) in tx.output.iter().enumerate() {
            db.set_utxo(&LocalUtxo {
                txout: out.clone(),
                outpoint: OutPoint {
                    txid,
                    vout: vout as u32,
                },
                keychain: KeychainKind::External,
                is_spent: false,
            })
            .unwrap();
        }

        txid
    }

    #[doc(hidden)]
    #[cfg(test)]
    /// Return a fake wallet that appears to be funded for testing.
    pub(crate) fn get_funded_wallet(
        descriptor: &str,
    ) -> (Wallet<AnyDatabase>, (String, Option<String>), bitcoin::Txid) {
        let descriptors = testutils!(@descriptors (descriptor));
        let wallet = Wallet::new(
            &descriptors.0,
            None,
            Network::Regtest,
            AnyDatabase::Memory(MemoryDatabase::new()),
        )
        .unwrap();

        let funding_address_kix = 0;

        let tx_meta = testutils! {
                @tx ( (@external descriptors, funding_address_kix) => 50_000 ) (@confirmations 1)
        };

        wallet
            .database_mut()
            .set_script_pubkey(
                &bitcoin::Address::from_str(&tx_meta.output.get(0).unwrap().to_address)
                    .unwrap()
                    .script_pubkey(),
                KeychainKind::External,
                funding_address_kix,
            )
            .unwrap();
        wallet
            .database_mut()
            .set_last_index(KeychainKind::External, funding_address_kix)
            .unwrap();

        let txid = populate_test_db(&mut *wallet.database_mut(), tx_meta, 100, false);

        (wallet, descriptors, txid)
    }
}
