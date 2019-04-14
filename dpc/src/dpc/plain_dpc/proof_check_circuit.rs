use algebra::{bytes::ToBytes, to_bytes, PairingEngine};
use failure::Error;
use snark::{Circuit, ConstraintSystem, SynthesisError};

use crate::{
    crypto_primitives::{CommitmentScheme, FixedLengthCRH},
    gadgets::Assignment,
};

use crate::{
    dpc::plain_dpc::{CommAndCRHPublicParameters, PlainDPCComponents, PrivatePredInput},
    gadgets::dpc::plain_dpc::execute_proof_check,
};

use algebra::utils::ToEngineFr;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: PlainDPCComponents"))]
pub struct ProofCheckVerifierInput<C: PlainDPCComponents> {
    pub comm_and_crh_pp: CommAndCRHPublicParameters<C>,
    pub predicate_comm:  <C::PredVkComm as CommitmentScheme>::Output,
    pub local_data_comm: <C::LocalDataComm as CommitmentScheme>::Output,
}

impl<C: PlainDPCComponents> ToEngineFr<C::ProofCheckE> for ProofCheckVerifierInput<C>
where
    <C::PredVkComm as CommitmentScheme>::Parameters: ToEngineFr<C::ProofCheckE>,
    <C::PredVkComm as CommitmentScheme>::Output: ToEngineFr<C::ProofCheckE>,

    <C::PredVkH as FixedLengthCRH>::Parameters: ToEngineFr<C::ProofCheckE>,

    <C::LocalDataComm as CommitmentScheme>::Parameters: ToEngineFr<C::E>,
    <C::LocalDataComm as CommitmentScheme>::Output: ToEngineFr<C::E>,
{
    fn to_engine_fr(&self) -> Result<Vec<<C::ProofCheckE as PairingEngine>::Fr>, Error> {
        let mut v = Vec::new();

        v.extend_from_slice(&self.comm_and_crh_pp.pred_vk_comm_pp.to_engine_fr()?);
        v.extend_from_slice(&self.comm_and_crh_pp.pred_vk_crh_pp.to_engine_fr()?);

        let local_data_comm_pp_fe =
            ToEngineFr::<C::E>::to_engine_fr(&self.comm_and_crh_pp.local_data_comm_pp)
                .map_err(|_| SynthesisError::AssignmentMissing)?;

        let local_data_comm_fe = ToEngineFr::<C::E>::to_engine_fr(&self.local_data_comm)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        // Then we convert these field elements into bytes
        let pred_input = [
            to_bytes![local_data_comm_pp_fe].map_err(|_| SynthesisError::AssignmentMissing)?,
            to_bytes![local_data_comm_fe].map_err(|_| SynthesisError::AssignmentMissing)?,
        ];

        // Then we convert them into `C::ProofCheckE::Fr` elements.
        v.extend_from_slice(&ToEngineFr::<C::ProofCheckE>::to_engine_fr(
            pred_input[0].as_slice(),
        )?);
        v.extend_from_slice(&ToEngineFr::<C::ProofCheckE>::to_engine_fr(
            pred_input[1].as_slice(),
        )?);

        v.extend_from_slice(&self.predicate_comm.to_engine_fr()?);
        Ok(v)
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: PlainDPCComponents"))]
pub struct ProofCheckCircuit<C: PlainDPCComponents> {
    comm_and_crh_parameters: Option<CommAndCRHPublicParameters<C>>,

    old_private_pred_inputs: Option<Vec<PrivatePredInput<C>>>,

    new_private_pred_inputs: Option<Vec<PrivatePredInput<C>>>,

    predicate_comm:  Option<<C::PredVkComm as CommitmentScheme>::Output>,
    predicate_rand:  Option<<C::PredVkComm as CommitmentScheme>::Randomness>,
    local_data_comm: Option<<C::LocalDataComm as CommitmentScheme>::Output>,
}

impl<C: PlainDPCComponents> ProofCheckCircuit<C> {
    pub fn blank(
        comm_and_crh_parameters: &CommAndCRHPublicParameters<C>,
        predicate_nizk_vk_and_proof: &PrivatePredInput<C>,
    ) -> Self {
        let num_input_records = C::NUM_INPUT_RECORDS;
        let num_output_records = C::NUM_OUTPUT_RECORDS;

        let old_private_pred_inputs =
            Some(vec![predicate_nizk_vk_and_proof.clone(); num_input_records]);
        let new_private_pred_inputs = Some(vec![
            predicate_nizk_vk_and_proof.clone();
            num_output_records
        ]);

        let predicate_comm = Some(<C::PredVkComm as CommitmentScheme>::Output::default());
        let predicate_rand = Some(<C::PredVkComm as CommitmentScheme>::Randomness::default());
        let local_data_comm = Some(<C::LocalDataComm as CommitmentScheme>::Output::default());

        Self {
            comm_and_crh_parameters: Some(comm_and_crh_parameters.clone()),

            old_private_pred_inputs,
            new_private_pred_inputs,

            predicate_comm,
            predicate_rand,
            local_data_comm,
        }
    }

    pub fn new(
        comm_and_crh_parameters: &CommAndCRHPublicParameters<C>,
        // Private pred input = Verification key and input
        // Commitment contains commitment to hash of death predicate vk.
        old_private_pred_inputs: &[PrivatePredInput<C>],

        // Private pred input = Verification key and input
        // Commitment contains commitment to hash of birth predicate vk.
        new_private_pred_inputs: &[PrivatePredInput<C>],

        predicate_comm: &<C::PredVkComm as CommitmentScheme>::Output,
        predicate_rand: &<C::PredVkComm as CommitmentScheme>::Randomness,
        local_data_comm: &<C::LocalDataComm as CommitmentScheme>::Output,
    ) -> Self {
        let num_input_records = C::NUM_INPUT_RECORDS;
        let num_output_records = C::NUM_OUTPUT_RECORDS;

        assert_eq!(num_input_records, old_private_pred_inputs.len());

        assert_eq!(num_output_records, new_private_pred_inputs.len());

        Self {
            comm_and_crh_parameters: Some(comm_and_crh_parameters.clone()),

            old_private_pred_inputs: Some(old_private_pred_inputs.to_vec()),

            new_private_pred_inputs: Some(new_private_pred_inputs.to_vec()),

            predicate_comm:  Some(predicate_comm.clone()),
            predicate_rand:  Some(predicate_rand.clone()),
            local_data_comm: Some(local_data_comm.clone()),
        }
    }
}

impl<C: PlainDPCComponents> Circuit<C::ProofCheckE> for ProofCheckCircuit<C>
where
    <C::LocalDataComm as CommitmentScheme>::Output: ToEngineFr<C::E>,
    <C::LocalDataComm as CommitmentScheme>::Parameters: ToEngineFr<C::E>,
{
    fn synthesize<CS: ConstraintSystem<C::ProofCheckE>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        execute_proof_check::<C, CS>(
            cs,
            self.comm_and_crh_parameters.get()?,
            self.old_private_pred_inputs.get()?.as_slice(),
            self.new_private_pred_inputs.get()?.as_slice(),
            self.predicate_comm.get()?,
            self.predicate_rand.get()?,
            self.local_data_comm.get()?,
        )?;
        Ok(())
    }
}
