package xor

import "testing"

func Test_Xor(t *testing.T) {
	type args struct {
		s1 string
		s2 string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test successfully",
			args: args{
				s1: "1c0111001f010100061a024b53535009181c",
				s2: "686974207468652062756c6c277320657965",
			},
			want:    "746865206b696420646f6e277420706c6179",
			wantErr: false,
		},
		{
			name: "Should throw error on input don't have the same length",
			args: args{
				s1: "1c0111001f010100061a024b5353500918",
				s2: "686974207468652062756c6c277320657965",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Should throw error on s1 or s2 or both are empty",
			args: args{
				s1: "",
				s2: "",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Should throw error on s1 is invalid hex string",
			args: args{
				s1: "GHIJKL",
				s2: "686974207468652062756c6c277320657965",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Should throw error on s2 is invalid hex string",
			args: args{
				s1: "6869742007468652062756c6c27732065796",
				s2: "ZG9sYW5kCg==",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Xor(tt.args.s1, tt.args.s2)
			if (err != nil) != tt.wantErr {
				t.Errorf("xor() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("xor() got = %v, want %v", got, tt.want)
			}
		})
	}
}
