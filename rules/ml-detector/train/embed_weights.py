#!/usr/bin/env python3
"""
Convert trained MLP weights to embedded Rust constants.

This script reads the JSON weights file and generates a Rust source file
with the weights embedded as compile-time constants. This allows the Wasm
module to include the trained model without runtime file loading.

Usage:
    python embed_weights.py --input mlp_weights.json --output ../src/weights.rs
"""

import argparse
import json
from pathlib import Path


def format_float_array(arr, indent=8):
    """Format a float array as Rust code."""
    lines = []
    line = " " * indent
    for i, val in enumerate(arr):
        formatted = f"{val:.10f}_f32"
        if i < len(arr) - 1:
            formatted += ","
        if len(line) + len(formatted) > 100:
            lines.append(line)
            line = " " * indent + formatted
        else:
            if line.strip():
                line += " " + formatted
            else:
                line += formatted
    if line.strip():
        lines.append(line)
    return "\n".join(lines)


def generate_rust_weights(weights_data):
    """Generate Rust source code with embedded weights."""
    layers = weights_data if isinstance(weights_data, list) else weights_data.get('layers', [])

    rust_code = '''//! Embedded MLP Weights
//!
//! Auto-generated from trained model weights.
//! Do not edit manually - regenerate using embed_weights.py

'''

    # Generate layer count constant
    rust_code += f"/// Number of layers in the network\n"
    rust_code += f"pub const NUM_LAYERS: usize = {len(layers)};\n\n"

    # Generate weight constants for each layer
    for layer_idx, layer in enumerate(layers):
        weights = layer['weights']
        biases = layer['biases']

        output_size = len(weights)
        input_size = len(weights[0]) if weights else 0

        rust_code += f"// Layer {layer_idx}: {input_size} -> {output_size}\n"

        # Weights as flattened array
        rust_code += f"pub const LAYER_{layer_idx}_WEIGHTS: &[f32] = &[\n"
        flat_weights = []
        for row in weights:
            flat_weights.extend(row)
        rust_code += format_float_array(flat_weights) + "\n"
        rust_code += "];\n\n"

        # Biases
        rust_code += f"pub const LAYER_{layer_idx}_BIASES: &[f32] = &[\n"
        rust_code += format_float_array(biases) + "\n"
        rust_code += "];\n\n"

        # Dimensions
        rust_code += f"pub const LAYER_{layer_idx}_INPUT_SIZE: usize = {input_size};\n"
        rust_code += f"pub const LAYER_{layer_idx}_OUTPUT_SIZE: usize = {output_size};\n\n"

    # Generate function to load embedded weights
    rust_code += '''/// Get embedded weights for a specific layer
pub fn get_layer_weights(layer_idx: usize) -> Option<(&'static [f32], &'static [f32], usize, usize)> {
    match layer_idx {
'''

    for layer_idx in range(len(layers)):
        rust_code += f"        {layer_idx} => Some((LAYER_{layer_idx}_WEIGHTS, LAYER_{layer_idx}_BIASES, LAYER_{layer_idx}_INPUT_SIZE, LAYER_{layer_idx}_OUTPUT_SIZE)),\n"

    rust_code += '''        _ => None,
    }
}

/// Load all embedded weights into layer format
pub fn load_embedded_weights() -> Vec<(Vec<Vec<f32>>, Vec<f32>)> {
    let mut layers = Vec::new();

    for layer_idx in 0..NUM_LAYERS {
        if let Some((weights, biases, input_size, output_size)) = get_layer_weights(layer_idx) {
            // Reshape flattened weights to 2D
            let mut weight_matrix = Vec::with_capacity(output_size);
            for i in 0..output_size {
                let start = i * input_size;
                let end = start + input_size;
                weight_matrix.push(weights[start..end].to_vec());
            }
            layers.push((weight_matrix, biases.to_vec()));
        }
    }

    layers
}

/// Default model threshold
pub const DEFAULT_THRESHOLD: f32 = 0.7;

/// Input feature size
pub const INPUT_SIZE: usize = 64;
'''

    return rust_code


def main():
    parser = argparse.ArgumentParser(description='Embed MLP weights in Rust code')
    parser.add_argument('--input', type=str,
                        default='mlp_weights.json',
                        help='Input weights JSON file')
    parser.add_argument('--output', type=str,
                        default='../src/weights.rs',
                        help='Output Rust file')

    args = parser.parse_args()

    # Read weights
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        return 1

    with open(input_path, 'r') as f:
        weights_data = json.load(f)

    # Generate Rust code
    rust_code = generate_rust_weights(weights_data)

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write(rust_code)

    # Calculate stats
    layers = weights_data if isinstance(weights_data, list) else weights_data.get('layers', [])
    total_params = 0
    for layer in layers:
        weights = layer['weights']
        biases = layer['biases']
        total_params += sum(len(row) for row in weights) + len(biases)

    print(f"Generated: {output_path}")
    print(f"  Layers: {len(layers)}")
    print(f"  Total parameters: {total_params}")
    print(f"  Estimated size: {total_params * 4 / 1024:.1f} KB (f32)")

    return 0


if __name__ == '__main__':
    exit(main())
